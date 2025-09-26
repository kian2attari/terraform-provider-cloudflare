package zero_trust_gateway_policy_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/acctest"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/utils"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func testAccCloudflareTeamsRuleConfigDns(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfigdns.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigDnsResolve(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfigdns-resolve.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigHttpAllow(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfighttp.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigHttpBlock(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfighttp-block.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigHttpIsolate(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfighttp-isolate.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigHttpIsolateV2(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfighttp-isolate-v2.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigL4(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfigl4.tf", rnd, accountID)
}

func TestAccCloudflareTeamsRule_Dns(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigDns(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12303)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("block")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("dns")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(dns.domains[*] == \"example.com\")")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("identity"), knownvalue.StringExact("any(identity.groups.name[*] in {\"finance\"})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("device_posture"), knownvalue.StringExact("")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("block_page_enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("block_reason"), knownvalue.StringExact("cuzs")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("ip_categories"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("ip_indicator_feeds"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("ignore_cname_category_matches"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("mon"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("tue"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("wed"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("thu"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("fri"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("sat"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("sun"), knownvalue.StringExact("08:00-12:30,13:30-17:00")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("schedule").AtMapKey("time_zone"), knownvalue.StringExact("America/New_York")),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_DNS_Resolve(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigDnsResolve(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12304)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("resolve")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("dns_resolver")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(dns.domains[*] == \"example.com\")")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("dns_resolvers").AtMapKey("ipv6").AtSliceIndex(0).AtMapKey("ip"), knownvalue.StringExact("2001:DB8::")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("dns_resolvers").AtMapKey("ipv4").AtSliceIndex(0).AtMapKey("ip"), knownvalue.StringExact("2.2.2.2")),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_HttpAllow(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigHttpAllow(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12305)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("allow")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("http")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(http.request.uri.security_category[*] in {22}) or any(http.request.uri.content_category[*] in {34})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("add_headers").AtMapKey("Xhello").AtSliceIndex(0), knownvalue.StringExact("abcd")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("add_headers").AtMapKey("Xhello").AtSliceIndex(1), knownvalue.StringExact("efg")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("check_session").AtMapKey("duration"), knownvalue.StringExact("1h2m9s")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("check_session").AtMapKey("enforce"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_HttpBlock(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigHttpBlock(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12306)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("block")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("http")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(http.request.uri.security_category[*] in {21}) or any(http.request.uri.content_category[*] in {32})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("block_page").AtMapKey("target_uri"), knownvalue.StringExact("https://examples.com")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("notification_settings").AtMapKey("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("notification_settings").AtMapKey("msg"), knownvalue.StringExact("msg")),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_HttpIsolate(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigHttpIsolate(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12307)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("isolate")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("http")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(http.request.uri.security_category[*] in {21}) or any(http.request.uri.content_category[*] in {32})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("copy"), knownvalue.StringExact("remote_only")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("keyboard"), knownvalue.StringExact("enabled")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("version"), knownvalue.StringExact("v1")),
				},
			},
			{
				Config: testAccCloudflareTeamsRuleConfigHttpIsolateV2(rnd, accountID),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(name, plancheck.ResourceActionUpdate),
						plancheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("version"), knownvalue.StringExact("v2")),
						plancheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("dcp"), knownvalue.Bool(true)),
						plancheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("dk"), knownvalue.Bool(true)),
					},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12307)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("isolate")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("http")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(http.request.uri.security_category[*] in {21}) or any(http.request.uri.content_category[*] in {32})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("version"), knownvalue.StringExact("v2")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("dcp"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("biso_admin_controls").AtMapKey("dk"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_L4(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigL4(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12308)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("l4_override")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("l4")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("net.dst.ip in {10.0.0.0/8} and net.dst.port in {80 443 8080 53} and not(net.dst.ip in {10.217.0.0/16})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("device_posture"), knownvalue.StringExact("any(device_posture.checks.passed[*] == \"51fe39d9-d584-48f5-9eed-36cd14ada791\")")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("l4override").AtMapKey("port"), knownvalue.Int64Exact(80)),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_NoSettings(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigDns(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				},
			},
			{
				Config: testAccCloudflareTeamsRuleConfigNoSettings(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("desc")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12301)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("block")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("dns")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(dns.domains[*] == \"example.com\")")),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func testAccCloudflareTeamsRuleConfigNoSettings(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfignosettings.tf", rnd, accountID)
}

func TestAccCloudflareTeamsRule_DNS_Override(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigDnsOverride(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("DNS override policy")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12400)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("override")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("dns")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(dns.domains[*] == \"example.com\")")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("override_ips").AtSliceIndex(0), knownvalue.StringExact("192.0.2.1")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("override_ips").AtSliceIndex(1), knownvalue.StringExact("192.0.2.2")),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

func TestAccCloudflareTeamsRule_HTTP_Redirect(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigHttpRedirect(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("HTTP redirect policy")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12401)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("redirect")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("http")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(http.request.uri.security_category[*] in {25})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("redirect").AtMapKey("target_uri"), knownvalue.StringExact("https://redirect.example.com")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("redirect").AtMapKey("include_context"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("rule_settings").AtMapKey("redirect").AtMapKey("preserve_path_and_query"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

// TestAccCloudflareTeamsRule_HTTP_Quarantine - DISABLED 
// The "quarantine" action is not supported by the API (returns "invalid action")
// This test is kept as documentation but commented out

func TestAccCloudflareTeamsRule_HTTP_Quarantine(t *testing.T) {
	t.Skip("quarantine action not supported by API - returns 'invalid action'")
}


// TestAccCloudflareTeamsRule_Egress - DISABLED
// This test requires dedicated IPv4 which is not available in test environment
// API requires both IPv4 and IPv6 for egress policies

func TestAccCloudflareTeamsRule_Egress(t *testing.T) {
	t.Skip("egress policies require dedicated IPv4/IPv6 which is not available in test environment")
}


func TestAccCloudflareTeamsRule_SafeSearch(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	rnd := utils.GenerateRandomResourceName()
	name := fmt.Sprintf("cloudflare_zero_trust_gateway_policy.%s", rnd)
	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
		},
		ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckCloudflareTeamsRuleDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCloudflareTeamsRuleConfigSafeSearch(rnd, accountID),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(name, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("description"), knownvalue.StringExact("Safe search policy")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("precedence"), knownvalue.Int64Exact(12404)),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("action"), knownvalue.StringExact("safesearch")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("filters").AtSliceIndex(0), knownvalue.StringExact("dns")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("traffic"), knownvalue.StringExact("any(dns.domains[*] in {\"google.com\" \"bing.com\" \"duckduckgo.com\"})")),
					statecheck.ExpectKnownValue(name, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
				},
			},
			{
				ResourceName:            name,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdPrefix:     fmt.Sprintf("%s/", accountID),
				ImportStateVerifyIgnore: []string{"sharable"},
			},
		},
	})
}

// TestAccCloudflareTeamsRule_MinimalToMaximal - DISABLED
// This test hits API drift issues where the API automatically populates rule_settings
// even when not specified, causing persistent plan changes (related to GitHub issue #5839)

func TestAccCloudflareTeamsRule_MinimalToMaximal(t *testing.T) {
	t.Skip("disabled due to API drift issues with rule_settings - see GitHub issue #5839")
}


// TestAccCloudflareTeamsRule_DNS_ResolveInternal - DISABLED
// This test requires a valid view_id which doesn't exist in test environment  
// The test is kept as documentation but commented out

func TestAccCloudflareTeamsRule_DNS_ResolveInternal(t *testing.T) {
	t.Skip("resolve_dns_internally requires valid view_id which doesn't exist in test environment")
}


// Helper functions for test configurations
func testAccCloudflareTeamsRuleConfigDnsOverride(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfigdns-override.tf", rnd, accountID)
}

func testAccCloudflareTeamsRuleConfigHttpRedirect(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfighttp-redirect.tf", rnd, accountID)
}

// testAccCloudflareTeamsRuleConfigHttpQuarantine - DISABLED (quarantine action not supported)
// func testAccCloudflareTeamsRuleConfigHttpQuarantine(rnd, accountID string) string {
// 	return acctest.LoadTestCase("teamsruleconfighttp-quarantine.tf", rnd, accountID)
// }

// testAccCloudflareTeamsRuleConfigEgress - DISABLED (requires dedicated IPv4/IPv6)
// func testAccCloudflareTeamsRuleConfigEgress(rnd, accountID string) string {
// 	return acctest.LoadTestCase("teamsruleconfigegress.tf", rnd, accountID)
// }

func testAccCloudflareTeamsRuleConfigSafeSearch(rnd, accountID string) string {
	return acctest.LoadTestCase("teamsruleconfigsafesearch.tf", rnd, accountID)
}

// testAccCloudflareTeamsRuleConfigMinimal - DISABLED (API drift issues)
// func testAccCloudflareTeamsRuleConfigMinimal(rnd, accountID string) string {
// 	return acctest.LoadTestCase("teamsruleconfigminimal.tf", rnd, accountID)
// }

// testAccCloudflareTeamsRuleConfigMaximal - DISABLED (API drift issues)  
// func testAccCloudflareTeamsRuleConfigMaximal(rnd, accountID string) string {
// 	return acctest.LoadTestCase("teamsruleconfigmaximal.tf", rnd, accountID)
// }

// testAccCloudflareTeamsRuleConfigDnsResolveInternal - DISABLED (requires valid view_id)
// func testAccCloudflareTeamsRuleConfigDnsResolveInternal(rnd, accountID string) string {
// 	return acctest.LoadTestCase("teamsruleconfigdns-resolve-internal.tf", rnd, accountID)
// }

func testAccCheckCloudflareTeamsRuleDestroy(s *terraform.State) error {
	client, clientErr := acctest.SharedV1Client() // TODO(terraform): replace with SharedV2Clent
	if clientErr != nil {
		tflog.Error(context.TODO(), fmt.Sprintf("failed to create Cloudflare client: %s", clientErr))
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "cloudflare_zero_trust_gateway_policy" {
			continue
		}

		_, err := client.TeamsRule(context.Background(), rs.Primary.Attributes[consts.AccountIDSchemaKey], rs.Primary.ID)
		if err == nil {
			return fmt.Errorf("teams rule still exists")
		}
	}

	return nil
}
