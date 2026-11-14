// Package check finds Kubernetes API versions that stop being served
// between two releases. Rules follow the official Deprecated API Migration
// Guide: https://kubernetes.io/docs/reference/using-api/deprecation-guide/
package check

// Rule describes one API version that is no longer served from release
// v1.<Removed>. Versions are Kubernetes minor numbers (25 means v1.25).
type Rule struct {
	APIVersion string
	Kinds      []string
	Removed    int
	Repl       string // replacement apiVersion, empty when there is none
	Since      int    // first release serving Repl
	Notes      string // field or behaviour changes
	Manual     bool   // true when more than the apiVersion line must change
}

// Deprecation describes an API that is deprecated but still served.
type Deprecation struct {
	APIVersion string
	Kinds      []string
	Deprecated int
	Repl       string
	Notes      string
}

const (
	daemonSetNotes  = "spec.templateGeneration is removed. spec.selector is now required and immutable. updateStrategy defaults to RollingUpdate."
	deploymentNotes = "spec.rollbackTo is removed. spec.selector is now required and immutable. Defaults change: progressDeadlineSeconds 600, revisionHistoryLimit 10, maxSurge and maxUnavailable 25%."
	statefulNotes   = "spec.selector is now required and immutable. updateStrategy defaults to RollingUpdate."
	replicaSetNotes = "spec.selector is now required and immutable."
	ingressNotes    = "spec.backend is renamed spec.defaultBackend. serviceName and servicePort move to service.name and service.port. pathType is required on every path."
	hpaNotes        = "targetAverageUtilization becomes target.averageUtilization with target.type: Utilization."
)

// Rules lists every core API removal from v1.16 through v1.32.
var Rules = []Rule{
	// v1.16
	{"extensions/v1beta1", []string{"NetworkPolicy"}, 16, "networking.k8s.io/v1", 8, "", false},
	{"extensions/v1beta1", []string{"DaemonSet"}, 16, "apps/v1", 9, daemonSetNotes, true},
	{"apps/v1beta2", []string{"DaemonSet"}, 16, "apps/v1", 9, daemonSetNotes, true},
	{"extensions/v1beta1", []string{"Deployment"}, 16, "apps/v1", 9, deploymentNotes, true},
	{"apps/v1beta1", []string{"Deployment"}, 16, "apps/v1", 9, deploymentNotes, true},
	{"apps/v1beta2", []string{"Deployment"}, 16, "apps/v1", 9, "spec.selector is now required and immutable. Check the changed defaults for progressDeadlineSeconds and revisionHistoryLimit.", true},
	{"apps/v1beta1", []string{"StatefulSet"}, 16, "apps/v1", 9, statefulNotes, true},
	{"apps/v1beta2", []string{"StatefulSet"}, 16, "apps/v1", 9, statefulNotes, true},
	{"extensions/v1beta1", []string{"ReplicaSet"}, 16, "apps/v1", 9, replicaSetNotes, true},
	{"apps/v1beta1", []string{"ReplicaSet"}, 16, "apps/v1", 9, replicaSetNotes, true},
	{"apps/v1beta2", []string{"ReplicaSet"}, 16, "apps/v1", 9, replicaSetNotes, true},
	{"extensions/v1beta1", []string{"PodSecurityPolicy"}, 16, "policy/v1beta1", 10, "", false},
	// v1.22
	{"admissionregistration.k8s.io/v1beta1", []string{"MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"}, 22, "admissionregistration.k8s.io/v1", 16, "sideEffects and admissionReviewVersions become required. failurePolicy defaults to Fail, matchPolicy to Equivalent, timeoutSeconds to 10. Webhook names must be unique.", true},
	{"apiextensions.k8s.io/v1beta1", []string{"CustomResourceDefinition"}, 22, "apiextensions.k8s.io/v1", 16, "A structural schema is required for every version. version, validation, subresources and additionalPrinterColumns move under spec.versions. JSONPath is renamed jsonPath. preserveUnknownFields: true is not allowed.", true},
	{"apiregistration.k8s.io/v1beta1", []string{"APIService"}, 22, "apiregistration.k8s.io/v1", 10, "", false},
	{"authentication.k8s.io/v1beta1", []string{"TokenReview"}, 22, "authentication.k8s.io/v1", 6, "", false},
	{"authorization.k8s.io/v1beta1", []string{"LocalSubjectAccessReview", "SelfSubjectAccessReview", "SubjectAccessReview", "SelfSubjectRulesReview"}, 22, "authorization.k8s.io/v1", 6, "spec.group is renamed spec.groups.", true},
	{"certificates.k8s.io/v1beta1", []string{"CertificateSigningRequest"}, 22, "certificates.k8s.io/v1", 19, "spec.signerName and spec.usages become required. The kubernetes.io/legacy-unknown signer is not allowed.", true},
	{"coordination.k8s.io/v1beta1", []string{"Lease"}, 22, "coordination.k8s.io/v1", 14, "", false},
	{"extensions/v1beta1", []string{"Ingress"}, 22, "networking.k8s.io/v1", 19, ingressNotes, true},
	{"networking.k8s.io/v1beta1", []string{"Ingress"}, 22, "networking.k8s.io/v1", 19, ingressNotes, true},
	{"networking.k8s.io/v1beta1", []string{"IngressClass"}, 22, "networking.k8s.io/v1", 19, "", false},
	{"rbac.authorization.k8s.io/v1beta1", []string{"ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"}, 22, "rbac.authorization.k8s.io/v1", 8, "", false},
	{"scheduling.k8s.io/v1beta1", []string{"PriorityClass"}, 22, "scheduling.k8s.io/v1", 14, "", false},
	{"storage.k8s.io/v1beta1", []string{"CSIDriver"}, 22, "storage.k8s.io/v1", 19, "", false},
	{"storage.k8s.io/v1beta1", []string{"CSINode"}, 22, "storage.k8s.io/v1", 17, "", false},
	{"storage.k8s.io/v1beta1", []string{"StorageClass"}, 22, "storage.k8s.io/v1", 6, "", false},
	{"storage.k8s.io/v1beta1", []string{"VolumeAttachment"}, 22, "storage.k8s.io/v1", 13, "", false},
	// v1.25
	{"batch/v1beta1", []string{"CronJob"}, 25, "batch/v1", 21, "", false},
	{"discovery.k8s.io/v1beta1", []string{"EndpointSlice"}, 25, "discovery.k8s.io/v1", 21, "Per-endpoint nodeName and zone fields replace the topology keys.", true},
	{"events.k8s.io/v1beta1", []string{"Event"}, 25, "events.k8s.io/v1", 19, "type is limited to Normal or Warning. involvedObject is renamed regarding. eventTime, series, reportingController and reportingInstance replace the older timestamp, count and source fields.", true},
	{"autoscaling/v2beta1", []string{"HorizontalPodAutoscaler"}, 25, "autoscaling/v2", 23, hpaNotes, true},
	{"policy/v1beta1", []string{"PodDisruptionBudget"}, 25, "policy/v1", 21, "Behaviour change: an empty spec.selector ({}) now selects every pod in the namespace. In v1beta1 it selected none.", true},
	{"policy/v1beta1", []string{"PodSecurityPolicy"}, 25, "", 0, "PodSecurityPolicy has no replacement API. Move to Pod Security Admission (namespace labels) or a policy engine such as Kyverno or Gatekeeper before upgrading.", true},
	{"node.k8s.io/v1beta1", []string{"RuntimeClass"}, 25, "node.k8s.io/v1", 20, "", false},
	// v1.26
	{"flowcontrol.apiserver.k8s.io/v1beta1", []string{"FlowSchema", "PriorityLevelConfiguration"}, 26, "flowcontrol.apiserver.k8s.io/v1beta2", 23, "", false},
	{"autoscaling/v2beta2", []string{"HorizontalPodAutoscaler"}, 26, "autoscaling/v2", 23, hpaNotes, true},
	// v1.27
	{"storage.k8s.io/v1beta1", []string{"CSIStorageCapacity"}, 27, "storage.k8s.io/v1", 24, "", false},
	// v1.29
	{"flowcontrol.apiserver.k8s.io/v1beta2", []string{"FlowSchema", "PriorityLevelConfiguration"}, 29, "flowcontrol.apiserver.k8s.io/v1beta3", 26, "spec.limited.assuredConcurrencyShares is renamed spec.limited.nominalConcurrencyShares.", true},
	// v1.32
	{"flowcontrol.apiserver.k8s.io/v1beta3", []string{"FlowSchema", "PriorityLevelConfiguration"}, 32, "flowcontrol.apiserver.k8s.io/v1", 29, "nominalConcurrencyShares defaults to 30 only when unset. An explicit 0 now stays 0.", true},
}

// Deprecations lists APIs that warn but are still served.
var Deprecations = []Deprecation{
	{"v1", []string{"Endpoints"}, 33, "discovery.k8s.io/v1 EndpointSlice", "The Endpoints API is deprecated from v1.33 and the API server returns a warning. It is still served. Plan a move to EndpointSlice."},
	{"v1", []string{"ComponentStatus"}, 19, "", "ComponentStatus has been deprecated since v1.19 and has no replacement API. Use component health endpoints instead."},
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func findRule(apiVersion, kind string) *Rule {
	for i := range Rules {
		if Rules[i].APIVersion == apiVersion && contains(Rules[i].Kinds, kind) {
			return &Rules[i]
		}
	}
	return nil
}

func findDeprecation(apiVersion, kind string) *Deprecation {
	for i := range Deprecations {
		if Deprecations[i].APIVersion == apiVersion && contains(Deprecations[i].Kinds, kind) {
			return &Deprecations[i]
		}
	}
	return nil
}
