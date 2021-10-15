// Copyright © 2020 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	whhttp "github.com/slok/kubewebhook/v2/pkg/http"
	whlog "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	whmetrics "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	whwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"
	"github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	kubernetesConfig "sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/banzaicloud/bank-vaults/pkg/webhook"
)

func init() {
	webhook.SetConfigDefaults()
}

func newK8SClient() (kubernetes.Interface, error) {
	kubeConfig, err := kubernetesConfig.GetConfig()
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(kubeConfig)
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
}

func handlerFor(config mutating.WebhookConfig, recorder whwebhook.MetricsRecorder) http.Handler {
	wh, err := mutating.NewWebhook(config)
	if err != nil {
		panic("error creating webhook: " + err.Error())
	}

	wh = whwebhook.NewMeasuredWebhook(recorder, wh)

	return whhttp.MustHandlerFor(whhttp.HandlerConfig{Webhook: wh, Logger: config.Logger})
}

type keypairReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
	logger   *logrus.Entry
}

func NewKeypairReloader(logger *logrus.Entry, certPath, keyPath string) (*keypairReloader, error) {
	result := &keypairReloader{
		certPath: certPath,
		keyPath:  keyPath,
		logger:   logger,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert

	return result, nil
}

func (kpr *keypairReloader) tryReloadingCert() error {
	kpr.logger.Warnf("Reloading certificate: %s and key: %s", kpr.certPath, kpr.keyPath)
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		kpr.logger.Fatalf("unable to load key pair: %s", err)
		return err
	}

	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert

	return nil
}

func (kpr *keypairReloader) watchDir() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		kpr.logger.Fatal(err)
		return err
	}

	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					kpr.tryReloadingCert()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				kpr.logger.Fatalf("event error: %s", err)
			}
		}
	}()

	kpr.logger.Infof("Watching certificate %s for updates", kpr.certPath)
	err = watcher.Add(kpr.certPath)
	if err != nil {
		kpr.logger.Fatalf("Unable to watch certificate %s for updates: %s", kpr.certPath, err)
		return err
	}

	kpr.logger.Infof("Watching key %s for updates", kpr.keyPath)
	err = watcher.Add(kpr.keyPath)
	if err != nil {
		kpr.logger.Fatalf("Unable to watch key %s for updates: %s", kpr.keyPath, err)
		return err
	}
	<-done

	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}

func main() {
	var logger *logrus.Entry
	{
		l := logrus.New()

		if viper.GetBool("enable_json_log") {
			l.SetFormatter(&logrus.JSONFormatter{})
		}

		lvl, err := logrus.ParseLevel(viper.GetString("log_level"))
		if err != nil {
			lvl = logrus.InfoLevel
		}
		l.SetLevel(lvl)

		logger = l.WithField("app", "vault-secrets-webhook")
	}

	k8sClient, err := newK8SClient()
	if err != nil {
		logger.Fatalf("error creating k8s client: %s", err)
	}

	mutatingWebhook, err := webhook.NewMutatingWebhook(logger, k8sClient)
	if err != nil {
		logger.Fatalf("error creating mutating webhook: %s", err)
	}

	whLogger := whlog.NewLogrus(logger)

	mutator := webhook.ErrorLoggerMutator(mutatingWebhook.VaultSecretsMutator, whLogger)

	promRegistry := prometheus.NewRegistry()
	metricsRecorder, err := whmetrics.NewRecorder(whmetrics.RecorderConfig{Registry: promRegistry})
	if err != nil {
		logger.Fatalf("error creating metrics recorder: %s", err)
	}

	promHandler := promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{})
	podHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-pods", Obj: &corev1.Pod{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	secretHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-secret", Obj: &corev1.Secret{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	configMapHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-configmap", Obj: &corev1.ConfigMap{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)
	objectHandler := handlerFor(mutating.WebhookConfig{ID: "vault-secrets-object", Obj: &unstructured.Unstructured{}, Logger: whLogger, Mutator: mutator}, metricsRecorder)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)
	mux.Handle("/secrets", secretHandler)
	mux.Handle("/configmaps", configMapHandler)
	mux.Handle("/objects", objectHandler)
	mux.Handle("/healthz", http.HandlerFunc(healthzHandler))

	telemetryAddress := viper.GetString("telemetry_listen_address")
	listenAddress := viper.GetString("listen_address")
	tlsCertFile := viper.GetString("tls_cert_file")
	tlsPrivateKeyFile := viper.GetString("tls_private_key_file")

	if len(telemetryAddress) > 0 {
		// Serving metrics without TLS on separated address
		go mutatingWebhook.ServeMetrics(telemetryAddress, promHandler)
	} else {
		mux.Handle("/metrics", promHandler)
	}

	if tlsCertFile == "" && tlsPrivateKeyFile == "" {
		logger.Infof("Listening on http://%s", listenAddress)
		err = http.ListenAndServe(listenAddress, mux)
	} else {
		kpr, err := NewKeypairReloader(logger, tlsCertFile, tlsPrivateKeyFile)
		if err != nil {
			logger.Fatal(err)
		}

		logger.Infof("Initiating watch of cert updates...")
		go kpr.watchDir()
		logger.Infof("Started watch....")

		tlsConf := &tls.Config{
			Certificates:   nil,
			GetCertificate: kpr.GetCertificateFunc(),
		}

		srv := &http.Server{
			Addr:      listenAddress,
			Handler:   mux,
			TLSConfig: tlsConf,
		}

		logger.Infof("Listening on https://%s", listenAddress)
		err = srv.ListenAndServeTLS("", "")
	}

	if err != nil {
		logger.Fatalf("error serving webhook: %s", err)
	}
}
