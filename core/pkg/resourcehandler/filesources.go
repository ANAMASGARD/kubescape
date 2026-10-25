package resourcehandler

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/opa-utils/objectsenvelopes/localworkload"
	"github.com/kubescape/opa-utils/reporthandling"
)

type fileResourceBatch struct {
	input     string
	workloads []workloadinterface.IMetadata
	sources   map[string]reporthandling.Source
}

// fileObservation keeps provenance alongside the object until its final ID is
// known. Merging maps earlier loses independent inputs with the same old ID.
type fileObservation struct {
	workload  workloadinterface.IMetadata
	source    reporthandling.Source
	hasSource bool
	root      string
	file      string
	path      string
	origin    string
}

// mergeFileResourceBatches gives local manifests one identity namespace while
// retaining their per-input provenance for reporting and remediation. Single-root
// scans keep their IDs; multiple roots use paths relative to their common ancestor.
func mergeFileResourceBatches(batches []fileResourceBatch) ([]workloadinterface.IMetadata, map[string]reporthandling.Source, error) {
	var observations []fileObservation
	roots := map[string]bool{}
	for _, batch := range batches {
		cloned := cautils.GetClonedPath(batch.input)
		for _, workload := range batch.workloads {
			source, hasSource := batch.sources[workload.GetID()]
			path, _ := workload.GetObject()[localworkload.PathKey].(string)
			observation := fileObservation{workload: workload, source: source, hasSource: hasSource, path: path, origin: batch.input}
			if cloned != "" {
				observation.origin = cloned
			}
			if hasSource && source.RelativePath != "" && filepath.IsAbs(source.Path) {
				observation.file = filepath.Clean(filepath.Join(source.Path, source.RelativePath))
				if filepath.IsAbs(source.RelativePath) {
					observation.file = filepath.Clean(source.RelativePath)
				}
				// Renderer paths describe generated objects, not raw documents.
				if cloned == "" && (source.FileType == reporthandling.SourceTypeYaml || source.FileType == reporthandling.SourceTypeJson) {
					observation.root = filepath.Clean(source.Path)
					roots[observation.root] = true
				}
			}
			observations = append(observations, observation)
		}
	}
	commonRoot := commonManifestRoot(roots)
	workloads := make([]workloadinterface.IMetadata, 0, len(observations))
	sources := make(map[string]reporthandling.Source, len(observations))
	seen := make(map[string]fileSourceCoordinate, len(observations))
	for _, observation := range observations {
		if len(roots) > 1 && observation.root != "" {
			colon := strings.LastIndexByte(observation.path, ':')
			if colon < 0 {
				return nil, nil, fmt.Errorf("manifest %q has no document index", observation.file)
			}
			path := observation.file
			if commonRoot != "" {
				var err error
				path, err = filepath.Rel(commonRoot, path)
				if err != nil {
					return nil, nil, fmt.Errorf("resolve manifest identity: %w", err)
				}
			}
			// Match the native path spelling used by loadFiles so scanning a
			// common parent and selecting its children produce the same IDs.
			localworkload.NewLocalWorkload(observation.workload.GetObject()).SetPath(path + observation.path[colon:])
		}
		id := observation.workload.GetID()
		coordinate := observation.coordinate()
		if previous, ok := seen[id]; ok {
			if !observation.hasSource || coordinate != previous {
				return nil, nil, fmt.Errorf("independent manifest sources share resource ID %q; scan these inputs separately", id)
			}
			continue // The same source and document was requested more than once.
		}
		seen[id] = coordinate
		workloads = append(workloads, observation.workload)
		if observation.hasSource {
			sources[id] = observation.source
		}
	}
	return workloads, sources, nil
}

type fileSourceCoordinate struct {
	origin, file, fileType, document string
}

func (observation fileObservation) coordinate() fileSourceCoordinate {
	coordinate := fileSourceCoordinate{
		origin: observation.origin, file: observation.source.RelativePath,
		fileType: observation.source.FileType, document: observation.path,
	}
	if observation.file != "" {
		coordinate.origin = ""
		coordinate.file = observation.file
		if observation.root != "" {
			if colon := strings.LastIndexByte(observation.path, ':'); colon >= 0 {
				coordinate.document = observation.path[colon:]
			}
		}
	}
	return coordinate
}

// An empty root means the inputs span Windows volumes. Absolute identity paths
// remain distinct in that case; file access still uses each source's own root.
func commonManifestRoot(roots map[string]bool) string {
	paths := make([]string, 0, len(roots))
	for root := range roots {
		paths = append(paths, root)
	}
	if len(paths) == 0 {
		return ""
	}
	sort.Strings(paths)
	common := paths[0]
	for _, path := range paths[1:] {
		for {
			rel, err := filepath.Rel(common, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				break
			}
			parent := filepath.Dir(common)
			if parent == common {
				return ""
			}
			common = parent
		}
	}
	return common
}
