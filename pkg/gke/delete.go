package gke

import (
	"context"
	"strings"
	"time"

	gkev1 "github.com/rancher/gke-operator/pkg/apis/gke.cattle.io/v1"
	"github.com/rancher/gke-operator/pkg/gke/services"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	waitSec      = 30
	backoffSteps = 12
)

var backoff = wait.Backoff{
	Duration: waitSec * time.Second,
	Steps:    backoffSteps,
}

// RemoveCluster attempts to delete a cluster and retries the delete request if the cluster is busy.
func RemoveCluster(ctx context.Context, gkeClient services.GKEClusterService, config *gkev1.GKEClusterConfig) error {
	clusterRRN := ClusterRRN(config.Spec.ProjectID, Location(config.Spec.Region, config.Spec.Zone), config.Spec.ClusterName)
	logrus.Infof("[DEBUG] Starting RemoveCluster for %s", clusterRRN)
	
	attempt := 0
	return wait.ExponentialBackoff(backoff, func() (bool, error) {
		attempt++
		logrus.Infof("[DEBUG] RemoveCluster attempt %d for %s", attempt, clusterRRN)
		
		// Check if context is already cancelled
		select {
		case <-ctx.Done():
			logrus.Errorf("[DEBUG] Context cancelled before ClusterDelete call (attempt %d) for %s: %v", attempt, clusterRRN, ctx.Err())
			return false, ctx.Err()
		default:
		}
		
		logrus.Infof("[DEBUG] Calling ClusterDelete for %s (attempt %d)", clusterRRN, attempt)
		_, err := gkeClient.ClusterDelete(ctx, clusterRRN)
		
		if err != nil {
			logrus.Errorf("[DEBUG] ClusterDelete returned error for %s (attempt %d): %v", clusterRRN, attempt, err)
		} else {
			logrus.Infof("[DEBUG] ClusterDelete succeeded for %s (attempt %d)", clusterRRN, attempt)
		}

		if err != nil && strings.Contains(err.Error(), errWait) {
			logrus.Infof("[DEBUG] Cluster %s is busy, retrying (attempt %d)", clusterRRN, attempt)
			return false, nil
		}
		if err != nil && strings.Contains(err.Error(), errNotFound) {
			logrus.Infof("[DEBUG] Cluster %s not found, considering deletion successful (attempt %d)", clusterRRN, attempt)
			return true, nil
		}
		if err != nil {
			logrus.Errorf("[DEBUG] Permanent error deleting cluster %s (attempt %d): %v", clusterRRN, attempt, err)
			return false, err
		}
		
		logrus.Infof("[DEBUG] Successfully deleted cluster %s (attempt %d)", clusterRRN, attempt)
		return true, nil
	})
}

// RemoveNodePool deletes a node pool
func RemoveNodePool(ctx context.Context, gkeClient services.GKEClusterService, config *gkev1.GKEClusterConfig, nodePoolName string) (Status, error) {
	_, err := gkeClient.NodePoolDelete(ctx,
		NodePoolRRN(config.Spec.ProjectID, Location(config.Spec.Region, config.Spec.Zone), config.Spec.ClusterName, nodePoolName))
	if err != nil && strings.Contains(err.Error(), errWait) {
		return Retry, nil
	}
	if err != nil && strings.Contains(err.Error(), errNotFound) {
		return NotChanged, nil
	}
	if err != nil {
		return NotChanged, err
	}
	return Changed, nil
}
