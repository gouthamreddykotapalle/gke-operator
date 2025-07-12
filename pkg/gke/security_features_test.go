package gke

import (
	"testing"

	gkev1 "github.com/rancher/gke-operator/pkg/apis/gke.cattle.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDatabaseEncryption(t *testing.T) {
	t.Run("DatabaseEncryptionEnabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.DatabaseEncryption = &gkev1.GKEDatabaseEncryption{
			State:   "ENCRYPTED",
			KeyName: "projects/test/locations/us-central1/keyRings/ring/cryptoKeys/key",
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.DatabaseEncryption == nil {
			t.Error("Expected DatabaseEncryption to be set when specified in config")
		}
		if request.Cluster.DatabaseEncryption.State != "ENCRYPTED" {
			t.Errorf("Expected DatabaseEncryption state to be ENCRYPTED, got %s", request.Cluster.DatabaseEncryption.State)
		}
	})

	t.Run("DatabaseEncryptionNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.DatabaseEncryption = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.DatabaseEncryption != nil {
			t.Error("Expected DatabaseEncryption to be nil when not specified in config")
		}
	})
}

func TestBinaryAuthorization(t *testing.T) {
	t.Run("BinaryAuthorizationEnabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.BinaryAuthorization = &gkev1.GKEBinaryAuthorization{
			Enabled: true,
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.BinaryAuthorization == nil {
			t.Error("Expected BinaryAuthorization to be set when specified in config")
		}
		if !request.Cluster.BinaryAuthorization.Enabled {
			t.Error("Expected BinaryAuthorization to be enabled")
		}
	})

	t.Run("BinaryAuthorizationDisabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.BinaryAuthorization = &gkev1.GKEBinaryAuthorization{
			Enabled: false,
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.BinaryAuthorization == nil {
			t.Error("Expected BinaryAuthorization to be set when specified in config")
		}
		if request.Cluster.BinaryAuthorization.Enabled {
			t.Error("Expected BinaryAuthorization to be disabled")
		}
	})

	t.Run("BinaryAuthorizationNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.BinaryAuthorization = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.BinaryAuthorization != nil {
			t.Error("Expected BinaryAuthorization to be nil when not specified in config")
		}
	})
}

func TestShieldedNodes(t *testing.T) {
	t.Run("ShieldedNodesEnabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.ShieldedNodes = &gkev1.GKEShieldedNodes{
			Enabled: true,
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.ShieldedNodes == nil {
			t.Error("Expected ShieldedNodes to be set when specified in config")
		}
		if !request.Cluster.ShieldedNodes.Enabled {
			t.Error("Expected ShieldedNodes to be enabled")
		}
	})

	t.Run("ShieldedNodesNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.ShieldedNodes = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.ShieldedNodes != nil {
			t.Error("Expected ShieldedNodes to be nil when not specified in config")
		}
	})
}

func TestWorkloadIdentity(t *testing.T) {
	t.Run("WorkloadIdentityConfigured", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.WorkloadIdentityConfig = &gkev1.GKEWorkloadIdentityConfig{
			WorkloadPool: "test-project.svc.id.goog",
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.WorkloadIdentityConfig == nil {
			t.Error("Expected WorkloadIdentityConfig to be set when specified in config")
		}
		if request.Cluster.WorkloadIdentityConfig.WorkloadPool != "test-project.svc.id.goog" {
			t.Errorf("Expected WorkloadPool to be test-project.svc.id.goog, got %s", request.Cluster.WorkloadIdentityConfig.WorkloadPool)
		}
	})

	t.Run("WorkloadIdentityNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.WorkloadIdentityConfig = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.WorkloadIdentityConfig != nil {
			t.Error("Expected WorkloadIdentityConfig to be nil when not specified in config")
		}
	})
}

func TestLegacyAbac(t *testing.T) {
	t.Run("LegacyAbacDisabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.LegacyAbac = &gkev1.GKELegacyAbac{
			Enabled: false,
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.LegacyAbac == nil {
			t.Error("Expected LegacyAbac to be set when specified in config")
		}
		if request.Cluster.LegacyAbac.Enabled {
			t.Error("Expected LegacyAbac to be disabled")
		}
	})

	t.Run("LegacyAbacNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.LegacyAbac = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.LegacyAbac != nil {
			t.Error("Expected LegacyAbac to be nil when not specified in config")
		}
	})
}

func TestMasterAuth(t *testing.T) {
	t.Run("MasterAuthWithClientCertDisabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.MasterAuth = &gkev1.GKEMasterAuth{
			Username: "",
			Password: "",
			ClientCertificateConfig: &gkev1.GKEClientCertificateConfig{
				IssueClientCertificate: false,
			},
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.MasterAuth == nil {
			t.Error("Expected MasterAuth to be set when specified in config")
		}
		if request.Cluster.MasterAuth.ClientCertificateConfig == nil {
			t.Error("Expected ClientCertificateConfig to be set")
		}
		if request.Cluster.MasterAuth.ClientCertificateConfig.IssueClientCertificate {
			t.Error("Expected ClientCertificate issuance to be disabled")
		}
	})

	t.Run("MasterAuthNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.MasterAuth = nil
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.MasterAuth != nil {
			t.Error("Expected MasterAuth to be nil when not specified in config")
		}
	})
}

func TestIntraNodeVisibility(t *testing.T) {
	t.Run("IntraNodeVisibilityEnabled", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.IntraNodeVisibilityConfig = &gkev1.GKEIntraNodeVisibilityConfig{
			Enabled: true,
		}
		
		request := NewClusterCreateRequest(config)
		if request.Cluster.NetworkConfig == nil {
			t.Error("Expected NetworkConfig to be set when IntraNodeVisibility is specified")
		}
		if !request.Cluster.NetworkConfig.EnableIntraNodeVisibility {
			t.Error("Expected IntraNodeVisibility to be enabled")
		}
	})

	t.Run("IntraNodeVisibilityNotSpecified", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.IntraNodeVisibilityConfig = nil
		
		request := NewClusterCreateRequest(config)
		// NetworkConfig might be nil or have EnableIntraNodeVisibility as false
		if request.Cluster.NetworkConfig != nil && request.Cluster.NetworkConfig.EnableIntraNodeVisibility {
			t.Error("Expected IntraNodeVisibility to not be enabled when not specified")
		}
	})
}

func TestNodePoolSecurityFeatures(t *testing.T) {
	t.Run("ShieldedInstanceConfig", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.NodePools[0].Config.ShieldedInstanceConfig = &gkev1.GKEShieldedInstanceConfig{
			EnableIntegrityMonitoring: true,
			EnableSecureBoot:         true,
		}
		
		request := NewClusterCreateRequest(config)
		if len(request.Cluster.NodePools) == 0 {
			t.Fatal("Expected at least one node pool")
		}
		nodePool := request.Cluster.NodePools[0]
		if nodePool.Config.ShieldedInstanceConfig == nil {
			t.Error("Expected ShieldedInstanceConfig to be set")
		}
		if !nodePool.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring {
			t.Error("Expected EnableIntegrityMonitoring to be true")
		}
		if !nodePool.Config.ShieldedInstanceConfig.EnableSecureBoot {
			t.Error("Expected EnableSecureBoot to be true")
		}
	})

	t.Run("WorkloadMetadataConfig", func(t *testing.T) {
		config := createBasicClusterConfig()
		config.Spec.NodePools[0].Config.WorkloadMetadataConfig = &gkev1.GKEWorkloadMetadataConfig{
			Mode: "GKE_METADATA",
		}
		
		request := NewClusterCreateRequest(config)
		if len(request.Cluster.NodePools) == 0 {
			t.Fatal("Expected at least one node pool")
		}
		nodePool := request.Cluster.NodePools[0]
		if nodePool.Config.WorkloadMetadataConfig == nil {
			t.Error("Expected WorkloadMetadataConfig to be set")
		}
		if nodePool.Config.WorkloadMetadataConfig.Mode != "GKE_METADATA" {
			t.Errorf("Expected Mode to be GKE_METADATA, got %s", nodePool.Config.WorkloadMetadataConfig.Mode)
		}
	})
}

// Helper function to create a basic cluster configuration for testing
func createBasicClusterConfig() *gkev1.GKEClusterConfig {
	nodePoolName := "default-pool"
	nodePoolVersion := "1.28.5-gke.1217000"
	initialNodeCount := int64(3)
	maxPodsConstraint := int64(110)
	enableKubernetesAlpha := false
	kubernetesVersion := "1.28.5-gke.1217000"
	clusterIpv4CidrBlock := "10.0.0.0/14"
	loggingService := "logging.googleapis.com/kubernetes"
	monitoringService := "monitoring.googleapis.com/kubernetes"
	network := "default"
	subnetwork := "default"
	networkPolicyEnabled := true
	maintenanceWindow := "03:00"

	return &gkev1.GKEClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: gkev1.GKEClusterConfigSpec{
			ClusterName:                    "test-cluster",
			EnableKubernetesAlpha:          &enableKubernetesAlpha,
			KubernetesVersion:              &kubernetesVersion,
			ClusterIpv4CidrBlock:           &clusterIpv4CidrBlock,
			LoggingService:                 &loggingService,
			MonitoringService:              &monitoringService,
			Network:                        &network,
			Subnetwork:                     &subnetwork,
			NetworkPolicyEnabled:           &networkPolicyEnabled,
			MaintenanceWindow:              &maintenanceWindow,
			ProjectID:                      "test-project",
			Region:                         "us-central1",
			Labels:                         map[string]string{},
			Locations:                      []string{"us-central1-a"},
			ClusterAddons: &gkev1.GKEClusterAddons{
				HTTPLoadBalancing:        true,
				HorizontalPodAutoscaling: true,
				NetworkPolicyConfig:      true,
			},
			IPAllocationPolicy: &gkev1.GKEIPAllocationPolicy{
				UseIPAliases:                true,
				ClusterIpv4CidrBlock:        "10.0.0.0/14",
				ServicesIpv4CidrBlock:       "10.4.0.0/19",
				ClusterSecondaryRangeName:   "",
				ServicesSecondaryRangeName:  "",
				SubnetworkName:              "",
			},
			PrivateClusterConfig: &gkev1.GKEPrivateClusterConfig{
				EnablePrivateNodes:    true,
				EnablePrivateEndpoint: false,
				MasterIpv4CidrBlock:   "172.16.0.0/28",
			},
			MasterAuthorizedNetworksConfig: &gkev1.GKEMasterAuthorizedNetworksConfig{
				Enabled:    true,
				CidrBlocks: []*gkev1.GKECidrBlock{},
			},
			NodePools: []gkev1.GKENodePoolConfig{
				{
					Name:              &nodePoolName,
					Version:           &nodePoolVersion,
					InitialNodeCount:  &initialNodeCount,
					MaxPodsConstraint: &maxPodsConstraint,
					Autoscaling: &gkev1.GKENodePoolAutoscaling{
						Enabled:      false,
						MinNodeCount: 1,
						MaxNodeCount: 3,
					},
					Management: &gkev1.GKENodePoolManagement{
						AutoRepair:  true,
						AutoUpgrade: true,
					},
					Config: &gkev1.GKENodeConfig{
						ImageType:      "COS_CONTAINERD",
						ServiceAccount: "default",
						DiskSizeGb:     100,
						DiskType:       "pd-standard",
						MachineType:    "e2-medium",
						Preemptible:    false,
					},
				},
			},
		},
	}
}
