package gke

import (
	"fmt"
	"testing"

	gkev1 "github.com/rancher/gke-operator/pkg/apis/gke.cattle.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// validateSecurityCompliance validates that a GKE cluster configuration meets security compliance requirements
func validateSecurityCompliance(config *gkev1.GKEClusterConfig) error {
	// Check if alpha features are disabled
	if config.Spec.EnableKubernetesAlpha != nil && *config.Spec.EnableKubernetesAlpha {
		return fmt.Errorf("alpha features must be disabled for security compliance")
	}

	// Check private cluster configuration
	if config.Spec.PrivateClusterConfig == nil || !config.Spec.PrivateClusterConfig.EnablePrivateNodes {
		return fmt.Errorf("private nodes must be enabled for security compliance")
	}

	// Check binary authorization
	if config.Spec.BinaryAuthorization == nil || !config.Spec.BinaryAuthorization.Enabled {
		return fmt.Errorf("binary authorization must be enabled for security compliance")
	}

	// Check shielded nodes
	if config.Spec.ShieldedNodes == nil || !config.Spec.ShieldedNodes.Enabled {
		return fmt.Errorf("shielded nodes must be enabled for security compliance")
	}

	// Check legacy ABAC is disabled
	if config.Spec.LegacyAbac != nil && config.Spec.LegacyAbac.Enabled {
		return fmt.Errorf("legacy ABAC must be disabled for security compliance")
	}

	// Check master auth is properly configured (no basic auth)
	if config.Spec.MasterAuth != nil {
		if config.Spec.MasterAuth.Username != "" || config.Spec.MasterAuth.Password != "" {
			return fmt.Errorf("basic authentication must be disabled for security compliance")
		}
		if config.Spec.MasterAuth.ClientCertificateConfig != nil &&
			config.Spec.MasterAuth.ClientCertificateConfig.IssueClientCertificate {
			return fmt.Errorf("client certificate issuance must be disabled for security compliance")
		}
	}

	// Check database encryption
	if config.Spec.DatabaseEncryption == nil || config.Spec.DatabaseEncryption.State != "ENCRYPTED" {
		return fmt.Errorf("database encryption must be enabled for security compliance")
	}

	// Check node pools for security requirements
	for i, nodePool := range config.Spec.NodePools {
		if nodePool.Config == nil {
			return fmt.Errorf("node pool %d config cannot be nil for security compliance", i)
		}

		// Check shielded instance config
		if nodePool.Config.ShieldedInstanceConfig == nil ||
			!nodePool.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring ||
			!nodePool.Config.ShieldedInstanceConfig.EnableSecureBoot {
			return fmt.Errorf("node pool %d must have shielded instance config with integrity monitoring and secure boot enabled", i)
		}

		// Check workload metadata config
		if nodePool.Config.WorkloadMetadataConfig == nil ||
			nodePool.Config.WorkloadMetadataConfig.Mode != "GKE_METADATA" {
			return fmt.Errorf("node pool %d must use GKE_METADATA mode for security compliance", i)
		}
	}

	return nil
}

// needsSecurityCompliance checks if a cluster configuration requires security compliance validation
func needsSecurityCompliance(config *gkev1.GKEClusterConfig) bool {
	// Check for security compliance label
	if config.Spec.Labels != nil {
		if compliance, exists := config.Spec.Labels["compliance"]; exists && compliance == "security" {
			return true
		}
	}

	// Check for security compliance annotation
	if config.ObjectMeta.Annotations != nil {
		if compliance, exists := config.ObjectMeta.Annotations["gke.cattle.io/security-compliance"]; exists && compliance == "true" {
			return true
		}
	}

	return false
}

func TestSecurityComplianceValidation(t *testing.T) {
	// Test case 1: Valid security compliant configuration
	t.Run("ValidSecurityCompliantConfig", func(t *testing.T) {
		config := createValidSecurityConfig()
		err := validateSecurityCompliance(config)
		if err != nil {
			t.Errorf("Expected valid security config to pass validation, got error: %v", err)
		}
	})

	// Test case 2: Alpha features enabled (should fail)
	t.Run("AlphaFeaturesEnabled", func(t *testing.T) {
		config := createValidSecurityConfig()
		alphaEnabled := true
		config.Spec.EnableKubernetesAlpha = &alphaEnabled
		err := validateSecurityCompliance(config)
		if err == nil {
			t.Error("Expected validation to fail when alpha features are enabled")
		}
	})

	// Test case 3: Private cluster not configured (should fail)
	t.Run("PrivateClusterNotConfigured", func(t *testing.T) {
		config := createValidSecurityConfig()
		config.Spec.PrivateClusterConfig = nil
		err := validateSecurityCompliance(config)
		if err == nil {
			t.Error("Expected validation to fail when private cluster is not configured")
		}
	})

	// Test case 4: Binary authorization disabled (should fail)
	t.Run("BinaryAuthorizationDisabled", func(t *testing.T) {
		config := createValidSecurityConfig()
		config.Spec.BinaryAuthorization = &gkev1.GKEBinaryAuthorization{Enabled: false}
		err := validateSecurityCompliance(config)
		if err == nil {
			t.Error("Expected validation to fail when binary authorization is disabled")
		}
	})

	// Test case 5: Node pool without shielded instance config (should fail)
	t.Run("NodePoolWithoutShieldedInstance", func(t *testing.T) {
		config := createValidSecurityConfig()
		config.Spec.NodePools[0].Config.ShieldedInstanceConfig = nil
		err := validateSecurityCompliance(config)
		if err == nil {
			t.Error("Expected validation to fail when node pool doesn't have shielded instance config")
		}
	})
}

func TestNeedsSecurityCompliance(t *testing.T) {
	// Test case 1: Security compliance label present
	t.Run("SecurityComplianceLabel", func(t *testing.T) {
		config := &gkev1.GKEClusterConfig{
			Spec: gkev1.GKEClusterConfigSpec{
				Labels: map[string]string{
					"compliance": "security",
				},
			},
		}
		if !needsSecurityCompliance(config) {
			t.Error("Expected security compliance to be needed when compliance label is set to security")
		}
	})

	// Test case 2: Security compliance annotation present
	t.Run("SecurityComplianceAnnotation", func(t *testing.T) {
		config := &gkev1.GKEClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"gke.cattle.io/security-compliance": "true",
				},
			},
		}
		if !needsSecurityCompliance(config) {
			t.Error("Expected security compliance to be needed when compliance annotation is set")
		}
	})

	// Test case 3: No compliance indicators
	t.Run("NoComplianceIndicators", func(t *testing.T) {
		config := &gkev1.GKEClusterConfig{}
		if needsSecurityCompliance(config) {
			t.Error("Expected security compliance to not be needed when no compliance indicators are present")
		}
	})
}

// Helper function to create a valid security compliant configuration
func createValidSecurityConfig() *gkev1.GKEClusterConfig {
	alphaDisabled := false
	nodePoolName := "default-pool"
	nodePoolVersion := "1.28.5-gke.1217000"
	initialNodeCount := int64(3)
	maxPodsConstraint := int64(110)

	return &gkev1.GKEClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: gkev1.GKEClusterConfigSpec{
			ClusterName:           "test-security-cluster",
			EnableKubernetesAlpha: &alphaDisabled,
			Labels: map[string]string{
				"compliance": "security",
			},
			PrivateClusterConfig: &gkev1.GKEPrivateClusterConfig{
				EnablePrivateNodes:    true,
				EnablePrivateEndpoint: true,
				MasterIpv4CidrBlock:   "172.16.0.0/28",
			},
			MasterAuthorizedNetworksConfig: &gkev1.GKEMasterAuthorizedNetworksConfig{
				Enabled: true,
				CidrBlocks: []*gkev1.GKECidrBlock{
					{
						CidrBlock:   "10.0.0.0/8",
						DisplayName: "Internal network",
					},
				},
			},
			DatabaseEncryption: &gkev1.GKEDatabaseEncryption{
				State:   "ENCRYPTED",
				KeyName: "projects/test/locations/us-central1/keyRings/ring/cryptoKeys/key",
			},
			BinaryAuthorization: &gkev1.GKEBinaryAuthorization{
				Enabled: true,
			},
			ShieldedNodes: &gkev1.GKEShieldedNodes{
				Enabled: true,
			},
			LegacyAbac: &gkev1.GKELegacyAbac{
				Enabled: false,
			},
			MasterAuth: &gkev1.GKEMasterAuth{
				Username: "",
				Password: "",
				ClientCertificateConfig: &gkev1.GKEClientCertificateConfig{
					IssueClientCertificate: false,
				},
			},
			IntraNodeVisibilityConfig: &gkev1.GKEIntraNodeVisibilityConfig{
				Enabled: true,
			},
			WorkloadIdentityConfig: &gkev1.GKEWorkloadIdentityConfig{
				WorkloadPool: "test-project.svc.id.goog",
			},
			NodePools: []gkev1.GKENodePoolConfig{
				{
					Name:              &nodePoolName,
					Version:           &nodePoolVersion,
					InitialNodeCount:  &initialNodeCount,
					MaxPodsConstraint: &maxPodsConstraint,
					Management: &gkev1.GKENodePoolManagement{
						AutoRepair:  true,
						AutoUpgrade: true,
					},
					Config: &gkev1.GKENodeConfig{
						ImageType:      "COS_CONTAINERD",
						ServiceAccount: "gke-nodes@test-project.iam.gserviceaccount.com",
						ShieldedInstanceConfig: &gkev1.GKEShieldedInstanceConfig{
							EnableIntegrityMonitoring: true,
							EnableSecureBoot:          true,
						},
						WorkloadMetadataConfig: &gkev1.GKEWorkloadMetadataConfig{
							Mode: "GKE_METADATA",
						},
					},
				},
			},
		},
	}
}
