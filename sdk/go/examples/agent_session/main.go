package main

import (
	"context"
	"log"

	contextdb "github.com/mikhailbovt/ContextDB/sdk/go"
)

func main() {
	client, err := contextdb.NewClient("http://127.0.0.1:8080", nil)
	if err != nil {
		log.Fatal(err)
	}
	requestContext := contextdb.RequestContext{
		RequestID: "example-start", WorkspaceID: "workspace-1", SubjectID: "subject-1",
		Audiences: []string{"subject:subject-1"}, Scopes: []string{"project:example"},
		Purpose: "assistant", Clearance: contextdb.SensitivityPrivate,
	}
	access := contextdb.AccessPolicy{
		WorkspaceID: "workspace-1", Scopes: []string{"project:example"}, Owners: []string{"subject-1"},
		Audience:              []string{"subject:subject-1"},
		AudiencePurposeGrants: map[string][]string{"subject:subject-1": {"assistant"}},
		Purposes:              []string{}, Sensitivity: contextdb.SensitivityPrivate,
		Consent: contextdb.ConsentGranted, Retrievable: true,
	}
	memory, err := contextdb.NewAgentSession(client, requestContext, access, "example-agent", "example-session")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	if _, err := memory.BeforeTurn(ctx, "What did we decide about the launch?", contextdb.BeforeTurnOptions{}); err != nil {
		log.Fatal(err)
	}
	if _, err := memory.AfterTurn(ctx, "What did we decide about the launch?", "We kept the staged rollout.", contextdb.AfterTurnOptions{}); err != nil {
		log.Fatal(err)
	}
}
