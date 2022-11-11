package starter

import (
	"flag"
	"os"

	"github.com/Azure/aks-tls-bootstrap/pkg/approver"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func Execute() {
	var metricsAddr string
	var webhookPort int
	var enableLeaderElection bool
	var healthAddr string

	flag.StringVar(&metricsAddr, "metrics-addr", "0", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true, "Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&webhookPort, "webhook-port", 0, "Webhook Server port, disabled by default. When enabled, the manager will only work as webhook server, no reconcilers are installed.")
	flag.StringVar(&healthAddr, "health-addr", ":9440", "The address the health endpoint binds to.")

	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	setupLog := ctrl.Log.WithName("setup")

	if err := approver.Run(os.Getenv("POD_NS"), metricsAddr, healthAddr, webhookPort, enableLeaderElection, setupLog); err != nil {
		setupLog.Error(err, "approver exited with error")
		os.Exit(1)
	}

	setupLog.Info("approver exited without error.")
	os.Exit(0)
}
