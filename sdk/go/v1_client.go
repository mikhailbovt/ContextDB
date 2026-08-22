package contextdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

func (client *Client) IngestFrame(ctx context.Context, request IngestFrame) (IngestAck, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	request.Value = normalizeIngestFrameValue(request.Value)
	var response IngestAck
	err := client.post(ctx, IngestFramePath, request, &response, validateIngestAck)
	return response, err
}

func (client *Client) Correct(ctx context.Context, request CorrectRequest) (MutationResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	request.Replacement = normalizeMemoryDocument(request.Replacement)
	var response MutationResponse
	err := client.post(ctx, CorrectPath, request, &response, validateMutationResponse)
	return response, err
}

func (client *Client) Forget(ctx context.Context, request ForgetRequest) (MutationResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response MutationResponse
	err := client.post(ctx, ForgetPath, request, &response, validateMutationResponse)
	return response, err
}

func (client *Client) Subscribe(ctx context.Context, request SubscribeRequest) (SubscriptionPage, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	if request.Filters == nil {
		request.Filters = []MemoryEventKind{}
	} else {
		request.Filters = append([]MemoryEventKind(nil), request.Filters...)
	}
	sort.Slice(request.Filters, func(left, right int) bool { return request.Filters[left] < request.Filters[right] })
	var response SubscriptionPage
	err := client.post(ctx, SubscribePath, request, &response, validateSubscriptionPage)
	return response, err
}

func (client *Client) GetNode(ctx context.Context, request GetMemoryRequest) (MemoryRecord, error) {
	return client.getMemory(ctx, GetNodePath, request)
}

func (client *Client) GetEvidence(ctx context.Context, request GetMemoryRequest) (MemoryRecord, error) {
	return client.getMemory(ctx, GetEvidencePath, request)
}

func (client *Client) GetConflict(ctx context.Context, request GetMemoryRequest) (MemoryRecord, error) {
	return client.getMemory(ctx, GetConflictPath, request)
}

func (client *Client) getMemory(ctx context.Context, path string, request GetMemoryRequest) (MemoryRecord, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response MemoryRecord
	err := client.post(ctx, path, request, &response, validateMemoryRecordObject)
	return response, err
}

func (client *Client) Traverse(ctx context.Context, request TraverseRequest) (TraverseResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	if request.StartIDs == nil {
		request.StartIDs = []string{}
	}
	if request.PredicateIDs == nil {
		request.PredicateIDs = []string{}
	} else {
		request.PredicateIDs = append([]string(nil), request.PredicateIDs...)
	}
	sort.Strings(request.PredicateIDs)
	var response TraverseResponse
	err := client.post(ctx, TraversePath, request, &response, validateTraverseResponse)
	return response, err
}

func (client *Client) GetTimeline(ctx context.Context, request GetTimelineRequest) (TimelineResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response TimelineResponse
	err := client.post(ctx, GetTimelinePath, request, &response, validateTimelineResponse)
	return response, err
}

func (client *Client) Bootstrap(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, BootstrapPath, request)
}

func (client *Client) Preflight(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, PreflightPath, request)
}

func (client *Client) Postflight(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, PostflightPath, request)
}

func (client *Client) Checkpoint(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, CheckpointPath, request)
}

func (client *Client) Resume(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, ResumePath, request)
}

func (client *Client) Handoff(ctx context.Context, request RuntimeRequest) (RuntimeResponse, error) {
	return client.runtime(ctx, HandoffPath, request)
}

func (client *Client) runtime(ctx context.Context, path string, request RuntimeRequest) (RuntimeResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response RuntimeResponse
	err := client.post(ctx, path, request, &response, validateRuntimeResponse)
	return response, err
}

func (client *Client) Consolidate(ctx context.Context, request MaintenanceRequest) (MaintenanceResponse, error) {
	return client.maintenance(ctx, ConsolidatePath, request)
}

func (client *Client) Reflect(ctx context.Context, request MaintenanceRequest) (MaintenanceResponse, error) {
	return client.maintenance(ctx, ReflectPath, request)
}

func (client *Client) Reindex(ctx context.Context, request MaintenanceRequest) (MaintenanceResponse, error) {
	return client.maintenance(ctx, ReindexPath, request)
}

func (client *Client) Compact(ctx context.Context, request MaintenanceRequest) (MaintenanceResponse, error) {
	return client.maintenance(ctx, CompactPath, request)
}

func (client *Client) maintenance(ctx context.Context, path string, request MaintenanceRequest) (MaintenanceResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response MaintenanceResponse
	err := client.post(ctx, path, request, &response, validateMaintenanceResponse)
	return response, err
}

func (client *Client) GetStatus(ctx context.Context, request GetStatusRequest) (StatusResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response StatusResponse
	err := client.post(ctx, GetStatusPath, request, &response, validateStatusResponse)
	return response, err
}

func (client *Client) CreateBackup(ctx context.Context, request CreateBackupRequest) (BackupResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response BackupResponse
	err := client.post(ctx, CreateBackupPath, request, &response, validateBackupResponse)
	return response, err
}

func (client *Client) RestoreBackup(ctx context.Context, request RestoreBackupRequest) (RestoreBackupResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response RestoreBackupResponse
	err := client.post(ctx, RestoreBackupPath, request, &response, validateRestoreBackupResponse)
	return response, err
}

func (client *Client) MigrateFormat(ctx context.Context, request MigrateFormatRequest) (StatusResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response StatusResponse
	err := client.post(ctx, MigrateFormatPath, request, &response, validateStatusResponse)
	return response, err
}

func (client *Client) highLevelWrite(ctx context.Context, path string, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	request.Access = normalizeAccessPolicy(request.Access)
	if request.References == nil {
		request.References = []string{}
	} else {
		request.References = append([]string(nil), request.References...)
	}
	sort.Strings(request.References)
	var response HighLevelMutationResponse
	err := client.post(ctx, path, request, &response, validateHighLevelMutationResponse)
	return response, err
}

func (client *Client) highLevelQuery(ctx context.Context, path string, request HighLevelQueryRequest) (RecallResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response RecallResponse
	err := client.post(ctx, path, request, &response, validateRecallResponse)
	return response, err
}

func (client *Client) highLevelControl(ctx context.Context, path string, request HighLevelControlRequest) (MutationResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	var response MutationResponse
	err := client.post(ctx, path, request, &response, validateMutationResponse)
	return response, err
}

func (client *Client) BeginSession(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, BeginSessionPath, request)
}
func (client *Client) BeforeTurn(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, BeforeTurnPath, request)
}
func (client *Client) AfterTurn(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, AfterTurnPath, request)
}
func (client *Client) ResolveReferent(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, ResolveReferentPath, request)
}
func (client *Client) RecallSharedHistory(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, RecallSharedHistoryPath, request)
}
func (client *Client) EndSession(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, EndSessionPath, request)
}
func (client *Client) BootstrapSubject(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, BootstrapSubjectPath, request)
}
func (client *Client) Remember(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, RememberPath, request)
}
func (client *Client) Pin(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, PinPath, request)
}
func (client *Client) Suppress(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, SuppressPath, request)
}
func (client *Client) ChangeAudience(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, ChangeAudiencePath, request)
}
func (client *Client) ChangeRetention(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, ChangeRetentionPath, request)
}
func (client *Client) ExplainMemory(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, ExplainMemoryPath, request)
}
func (client *Client) ListSubjectMemories(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, ListSubjectMemoriesPath, request)
}
func (client *Client) CreateMemorySubject(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, CreateMemorySubjectPath, request)
}
func (client *Client) CreateRelationshipSpace(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, CreateRelationshipSpacePath, request)
}
func (client *Client) GetContinuityProfile(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, GetContinuityProfilePath, request)
}
func (client *Client) UpdateConfiguredRole(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, UpdateConfiguredRolePath, request)
}
func (client *Client) MigrateAgentRuntime(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, MigrateAgentRuntimePath, request)
}
func (client *Client) PublishToSharedMemory(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, PublishToSharedMemoryPath, request)
}
func (client *Client) RevokeSharedMemory(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, RevokeSharedMemoryPath, request)
}
func (client *Client) IngestArtifact(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, IngestArtifactPath, request)
}
func (client *Client) AttachArtifactToEpisode(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, AttachArtifactToEpisodePath, request)
}
func (client *Client) AddDerivedRepresentation(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, AddDerivedRepresentationPath, request)
}
func (client *Client) AddEvidenceSelector(ctx context.Context, request HighLevelWriteRequest) (HighLevelMutationResponse, error) {
	return client.highLevelWrite(ctx, AddEvidenceSelectorPath, request)
}
func (client *Client) GetArtifactMetadata(ctx context.Context, request HighLevelQueryRequest) (RecallResponse, error) {
	return client.highLevelQuery(ctx, GetArtifactMetadataPath, request)
}
func (client *Client) DeleteArtifactLineage(ctx context.Context, request HighLevelControlRequest) (MutationResponse, error) {
	return client.highLevelControl(ctx, DeleteArtifactLineagePath, request)
}

func (client *Client) ExportSubject(ctx context.Context, request HighLevelTransferRequest) (ExportResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	if request.Bytes == nil {
		request.Bytes = ByteArray{}
	}
	var response ExportResponse
	err := client.post(ctx, ExportSubjectPath, request, &response, validateExportResponse)
	return response, err
}

func (client *Client) ImportSubject(ctx context.Context, request HighLevelTransferRequest) (ImportResponse, error) {
	request.Context = normalizeAuthenticatedContext(request.Context)
	if request.Bytes == nil {
		request.Bytes = ByteArray{}
	}
	var response ImportResponse
	err := client.post(ctx, ImportSubjectPath, request, &response, validateImportResponse)
	return response, err
}

func normalizeAuthenticatedContext(value AuthenticatedRequestContext) AuthenticatedRequestContext {
	value.Request = normalizeRequestContext(value.Request)
	if value.CapabilityGrants == nil {
		value.CapabilityGrants = []Capability{}
	} else {
		value.CapabilityGrants = append([]Capability(nil), value.CapabilityGrants...)
	}
	sort.Slice(value.CapabilityGrants, func(left, right int) bool {
		return value.CapabilityGrants[left] < value.CapabilityGrants[right]
	})
	return value
}

func normalizeMemoryDocument(value MemoryDocument) MemoryDocument {
	value.Access = normalizeAccessPolicy(value.Access)
	if value.Links.Supersedes == nil {
		value.Links.Supersedes = []string{}
	} else {
		value.Links.Supersedes = append([]string(nil), value.Links.Supersedes...)
	}
	if value.Links.Evidence == nil {
		value.Links.Evidence = []string{}
	} else {
		value.Links.Evidence = append([]string(nil), value.Links.Evidence...)
	}
	if value.Links.ConflictMembers == nil {
		value.Links.ConflictMembers = []string{}
	} else {
		value.Links.ConflictMembers = append([]string(nil), value.Links.ConflictMembers...)
	}
	sort.Strings(value.Links.Supersedes)
	sort.Strings(value.Links.Evidence)
	sort.Strings(value.Links.ConflictMembers)
	if value.Attributes == nil {
		value.Attributes = map[string]any{}
	}
	return value
}

func sortAccessPolicy(value AccessPolicy) AccessPolicy {
	sort.Strings(value.Scopes)
	sort.Strings(value.Owners)
	sort.Strings(value.Audience)
	sort.Strings(value.Purposes)
	for _, purposes := range value.AudiencePurposeGrants {
		sort.Strings(purposes)
	}
	return value
}

func normalizeIngestFrameValue(value IngestFrameValue) IngestFrameValue {
	switch payload := value.Value.(type) {
	case SourceRevisionManifest:
		if payload.Attributes == nil {
			payload.Attributes = map[string]string{}
		}
		value.Value = payload
	case StreamObservation:
		if payload.Metadata == nil {
			payload.Metadata = map[string]any{}
		}
		payload.Access = normalizeAccessPolicy(payload.Access)
		value.Value = payload
	}
	return value
}

func validateMutationResponse(object map[string]any) error {
	return validateObserveResponse(object)
}

func validateHighLevelMutationResponse(object map[string]any) error {
	if err := requireKeys(object, "operation", "logical_id", "policy_result", "semantic_status", "receipt"); err != nil {
		return err
	}
	for _, key := range []string{"operation", "logical_id"} {
		if err := requireString(object[key], key); err != nil {
			return err
		}
	}
	if err := requireEnum(object["policy_result"], "policy_result", "accepted"); err != nil {
		return err
	}
	if err := requireEnum(object["semantic_status"], "semantic_status", "pending"); err != nil {
		return err
	}
	receipt, ok := object["receipt"].(map[string]any)
	if !ok {
		return errors.New("receipt must be an object")
	}
	return validateObserveResponse(receipt)
}

func validateIngestAck(object map[string]any) error {
	required := []string{"stream_id", "position", "disposition", "frame_digest", "resume_cursor", "commit_seq", "partial_result_refs"}
	if len(object) != len(required) && len(object) != len(required)+1 {
		return errors.New("response object has missing or unknown fields")
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return errors.New("response object has missing or unknown fields")
		}
	}
	if len(object) == len(required)+1 {
		if _, ok := object["lease_expires_at_ms"]; !ok {
			return errors.New("response object has missing or unknown fields")
		}
	}
	if deadline, ok := object["lease_expires_at_ms"]; ok {
		if err := requireUint(deadline, "lease_expires_at_ms"); err != nil {
			return err
		}
	}
	for _, key := range []string{"stream_id", "frame_digest", "resume_cursor"} {
		if err := requireString(object[key], key); err != nil {
			return err
		}
	}
	if err := requireUint(object["position"], "position"); err != nil {
		return err
	}
	if err := requireEnum(object["disposition"], "disposition", "accepted", "replayed", "snapshot_committed"); err != nil {
		return err
	}
	if object["commit_seq"] != nil {
		if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
			return err
		}
	}
	return requireStringArray(object["partial_result_refs"], "partial_result_refs")
}

func validateSubscriptionPage(object map[string]any) error {
	if err := requireKeys(object, "events", "resume_cursor", "caught_up"); err != nil {
		return err
	}
	events, ok := object["events"].([]any)
	if !ok {
		return errors.New("events must be an array")
	}
	for _, value := range events {
		event, err := nestedObject(value, "memory event")
		if err != nil {
			return err
		}
		if err := requireKeys(event, "event_id", "commit_seq", "ordinal", "kind", "object_refs", "attributes"); err != nil {
			return err
		}
		if err := requireString(event["event_id"], "event_id"); err != nil {
			return err
		}
		if err := requireUint(event["commit_seq"], "commit_seq"); err != nil {
			return err
		}
		if err := requireUintBits(event["ordinal"], "ordinal", 32); err != nil {
			return err
		}
		if err := requireEnum(event["kind"], "event kind", memoryEventKinds...); err != nil {
			return err
		}
		if err := requireStringArray(event["object_refs"], "object_refs"); err != nil {
			return err
		}
		if err := requireStringMap(event["attributes"], "event attributes"); err != nil {
			return err
		}
	}
	if err := requireString(object["resume_cursor"], "resume_cursor"); err != nil {
		return err
	}
	if _, ok := object["caught_up"].(bool); !ok {
		return errors.New("caught_up must be a boolean")
	}
	return nil
}

func validateMemoryRecordObject(object map[string]any) error {
	return validateMemoryRecord(object)
}

func validateMemoryRecord(object map[string]any) error {
	if err := requireKeys(object, "document", "revision", "transaction_from", "transaction_to"); err != nil {
		return err
	}
	document, err := nestedObject(object["document"], "memory document")
	if err != nil {
		return err
	}
	if err := validateMemoryDocument(document); err != nil {
		return err
	}
	if err := requireUintBits(object["revision"], "revision", 32); err != nil {
		return err
	}
	if err := requireUint(object["transaction_from"], "transaction_from"); err != nil {
		return err
	}
	if object["transaction_to"] != nil {
		return requireUint(object["transaction_to"], "transaction_to")
	}
	return nil
}

func validateMemoryDocument(object map[string]any) error {
	if err := requireKeys(object, "id", "kind", "access", "valid_time", "lifecycle", "links", "value", "search_text", "vector", "attributes"); err != nil {
		return err
	}
	if err := requireString(object["id"], "memory id"); err != nil {
		return err
	}
	if err := requireEnum(object["kind"], "memory kind", memoryRecordKinds...); err != nil {
		return err
	}
	access, err := nestedObject(object["access"], "access policy")
	if err != nil {
		return err
	}
	if err := validateAccessPolicy(access); err != nil {
		return err
	}
	validTime, err := nestedObject(object["valid_time"], "valid_time")
	if err != nil {
		return err
	}
	if err := requireKeys(validTime, "from", "to"); err != nil {
		return err
	}
	for _, key := range []string{"from", "to"} {
		if validTime[key] != nil {
			number, ok := validTime[key].(json.Number)
			if !ok {
				return fmt.Errorf("valid_time.%s must be an i128 integer", key)
			}
			if _, err := NewInt128(number.String()); err != nil {
				return fmt.Errorf("valid_time.%s must be an i128 integer", key)
			}
		}
	}
	if err := requireEnum(object["lifecycle"], "memory lifecycle", "active", "superseded", "retracted", "suppressed"); err != nil {
		return err
	}
	links, err := nestedObject(object["links"], "memory links")
	if err != nil {
		return err
	}
	if err := validateMemoryLinks(links); err != nil {
		return err
	}
	if object["search_text"] != nil {
		if err := requireString(object["search_text"], "search_text"); err != nil {
			return err
		}
	}
	if object["vector"] != nil {
		values, ok := object["vector"].([]any)
		if !ok {
			return errors.New("vector must be an array or null")
		}
		for _, value := range values {
			if err := requireFiniteF32(value, "vector item"); err != nil {
				return err
			}
		}
	}
	if _, ok := object["attributes"].(map[string]any); !ok {
		return errors.New("attributes must be an object")
	}
	return nil
}

func validateAccessPolicy(object map[string]any) error {
	if err := requireKeys(object, "workspace_id", "scopes", "owners", "audience", "audience_purpose_grants", "purposes", "sensitivity", "consent", "retrievable"); err != nil {
		return err
	}
	if err := requireString(object["workspace_id"], "workspace_id"); err != nil {
		return err
	}
	for _, key := range []string{"scopes", "owners", "audience", "purposes"} {
		if err := requireStringArray(object[key], key); err != nil {
			return err
		}
	}
	grants, ok := object["audience_purpose_grants"].(map[string]any)
	if !ok {
		return errors.New("audience_purpose_grants must be an object")
	}
	for key, value := range grants {
		if err := requireStringArray(value, "audience_purpose_grants."+key); err != nil {
			return err
		}
	}
	if err := requireEnum(object["sensitivity"], "sensitivity", "public", "internal", "private", "restricted"); err != nil {
		return err
	}
	if err := requireEnum(object["consent"], "consent", "granted", "unknown", "denied"); err != nil {
		return err
	}
	if _, ok := object["retrievable"].(bool); !ok {
		return errors.New("retrievable must be a boolean")
	}
	return nil
}

func validateMemoryLinks(object map[string]any) error {
	if err := requireKeys(object, "subject", "source", "target", "predicate", "conflict_set", "supersedes", "evidence", "conflict_members", "single_valued"); err != nil {
		return err
	}
	for _, key := range []string{"subject", "source", "target", "predicate", "conflict_set"} {
		if object[key] != nil {
			if err := requireString(object[key], "links."+key); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"supersedes", "evidence", "conflict_members"} {
		if err := requireStringArray(object[key], "links."+key); err != nil {
			return err
		}
	}
	if _, ok := object["single_valued"].(bool); !ok {
		return errors.New("single_valued must be a boolean")
	}
	return nil
}

func validateTraverseResponse(object map[string]any) error {
	if err := requireKeys(object, "node_ids", "snapshot_seq", "authorized_candidates", "watermarks"); err != nil {
		return err
	}
	if err := requireStringArray(object["node_ids"], "node_ids"); err != nil {
		return err
	}
	for _, key := range []string{"snapshot_seq", "authorized_candidates"} {
		if err := requireUint(object[key], key); err != nil {
			return err
		}
	}
	return validateWatermarks(object["watermarks"])
}

func validateTimelineResponse(object map[string]any) error {
	if err := requireKeys(object, "revisions", "snapshot_seq", "watermarks"); err != nil {
		return err
	}
	revisions, ok := object["revisions"].([]any)
	if !ok {
		return errors.New("revisions must be an array")
	}
	for _, value := range revisions {
		record, err := nestedObject(value, "memory record")
		if err != nil {
			return err
		}
		if err := validateMemoryRecord(record); err != nil {
			return err
		}
	}
	if err := requireUint(object["snapshot_seq"], "snapshot_seq"); err != nil {
		return err
	}
	return validateWatermarks(object["watermarks"])
}

func validateRuntimeResponse(object map[string]any) error {
	if err := requireKeys(object, "operation_id", "payload"); err != nil {
		return err
	}
	return requireString(object["operation_id"], "operation_id")
}

func validateMaintenanceResponse(object map[string]any) error {
	return validateRuntimeResponse(object)
}

func validateStatusResponse(object map[string]any) error {
	if err := requireKeys(object, "schema_version", "profile", "commit_seq", "watermarks", "capability_manifest"); err != nil {
		return err
	}
	if err := requireUintBits(object["schema_version"], "schema_version", 16); err != nil {
		return err
	}
	if err := requireString(object["profile"], "profile"); err != nil {
		return err
	}
	if err := requireUint(object["commit_seq"], "commit_seq"); err != nil {
		return err
	}
	if err := validateWatermarks(object["watermarks"]); err != nil {
		return err
	}
	manifest, err := nestedObject(object["capability_manifest"], "capability manifest")
	if err != nil {
		return err
	}
	if err := validateCapabilityManifest(manifest); err != nil {
		return err
	}
	if manifest["profile"] != object["profile"] {
		return errors.New("status profile does not match capability manifest profile")
	}
	return nil
}

func validateCapabilityManifest(object map[string]any) error {
	if err := requireKeys(object, "schema_version", "profile", "server_v1_release_ready", "capabilities"); err != nil {
		return err
	}
	version, ok := object["schema_version"].(json.Number)
	if !ok || version.String() != "1" {
		return errors.New("unsupported capability manifest schema_version")
	}
	if err := requireString(object["profile"], "capability manifest profile"); err != nil {
		return err
	}
	if _, ok := object["server_v1_release_ready"].(bool); !ok {
		return errors.New("server_v1_release_ready must be a boolean")
	}
	capabilities, err := nestedObject(object["capabilities"], "capability manifest capabilities")
	if err != nil {
		return err
	}
	for capability, state := range capabilities {
		if err := requireEnum(state, "capability state for "+capability, "available", "compiled_only", "unsupported"); err != nil {
			return err
		}
	}
	return nil
}

func validateBackupResponse(object map[string]any) error {
	return validateExportResponse(object)
}

func validateRestoreBackupResponse(object map[string]any) error {
	return validateImportResponse(object)
}

func requireString(value any, name string) error {
	if _, ok := value.(string); !ok {
		return fmt.Errorf("%s must be a string", name)
	}
	return nil
}

func requireStringMap(value any, name string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be an object", name)
	}
	for _, item := range object {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("%s values must be strings", name)
		}
	}
	return nil
}

func requireUintBits(value any, name string, bits int) error {
	number, ok := value.(json.Number)
	if !ok {
		return fmt.Errorf("%s must be an unsigned integer", name)
	}
	if _, err := strconv.ParseUint(number.String(), 10, bits); err != nil {
		return fmt.Errorf("%s must be an unsigned integer", name)
	}
	return nil
}

func requireEnum(value any, name string, allowed ...string) error {
	raw, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s must be a string", name)
	}
	for _, item := range allowed {
		if raw == item {
			return nil
		}
	}
	return fmt.Errorf("%s is not a canonical enum value", name)
}

var memoryRecordKinds = []string{
	"node", "claim", "edge", "conflict", "evidence", "candidate", "semantic_object", "runtime_state", "domain_extension",
}

var memoryEventKinds = []string{
	"node_changed", "claim_changed", "open_loop_triggered", "index_watermark_advanced", "conflict_resolved",
	"source_invalidated", "operation_progress", "security_event", "observation_accepted", "record_changed",
}
