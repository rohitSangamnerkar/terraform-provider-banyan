package banyan

import (
	"context"
	"encoding/json"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// The role resource. For more information on Banyan roles, please see the documentation:
func resourceRoleV2() *schema.Resource {
	return &schema.Resource{
		Description:   "The role resource represents a group of users in the organization. For more information on Banyan roles, see the [documentation.](https://docs.banyansecurity.io/docs/feature-guides/administer-security-policies/roles/manage-roles/)",
		CreateContext: resourceV2RoleCreate,
		ReadContext:   resourceV2RoleRead,
		UpdateContext: resourceV2RoleUpdate,
		DeleteContext: resourceV2RoleDelete,
		Schema:        RoleV2Schema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func RoleV2Schema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			ForceNew:    true,
			Description: "Name of the role",
		},
		"description": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Description of the role",
		},
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the role in Banyan",
		},
		"container_fqdn": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "FQDN for the container",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"image": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Image",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"repo_tag": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Repo Tag",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"service_account": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Service accounts to be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"user_group": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Names of the groups (from your IdP) which will be included in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"email": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Email addresses for the users in the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"device_ownership": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Device ownership specification for the role",
			Elem: &schema.Schema{
				Type:         schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{"Corporate Dedicated", "Corporate Shared", "Employee Owned", "Other"}, false),
			},
		},
		"platform": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Platform type which is required by the role",
			Elem: &schema.Schema{
				Type:         schema.TypeString,
				ValidateFunc: validation.StringInSlice([]string{"Windows", "macOS", "Linux", "iOS", "Android", "Unregistered"}, false),
			},
		},
		"known_device_only": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enforces whether the role requires known devices only for access",
		},
		"mdm_present": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Enforces whether the role requires an MDM to be present on the device",
		},
		"serial_numbers": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "List of Serial Numbers belonging to devices for the role",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}
	return
}

func V2RoleFromState(d *schema.ResourceData) (r role.CreateRole) {
	r = role.CreateRole{
		Metadata: role.Metadata{
			ID:          d.Get("id").(string),
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Tags: role.Tags{
				Template: "USER",
			},
		},
		Kind:       "BanyanRole",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec: role.Spec{
			ContainerFQDN:   convertSchemaSetToStringSlice(d.Get("container_fqdn").(*schema.Set)),
			Image:           convertSchemaSetToStringSlice(d.Get("image").(*schema.Set)),
			RepoTag:         convertSchemaSetToStringSlice(d.Get("repo_tag").(*schema.Set)),
			LabelSelector:   []role.LabSel{},
			ServiceAccts:    convertSchemaSetToStringSlice(d.Get("service_account").(*schema.Set)),
			UserGroup:       convertSchemaSetToStringSlice(d.Get("user_group").(*schema.Set)),
			Email:           convertSchemaSetToStringSlice(d.Get("email").(*schema.Set)),
			DeviceOwnership: convertSchemaSetToStringSlice(d.Get("device_ownership").(*schema.Set)),
			Platform:        convertSchemaSetToStringSlice(d.Get("platform").(*schema.Set)),
			KnownDeviceOnly: d.Get("known_device_only").(bool),
			MDMPresent:      d.Get("mdm_present").(bool),
			SerialNumbers:   convertSchemaSetToStringSlice(d.Get("serial_numbers").(*schema.Set)),
		},
	}
	return
}

func resourceV2RoleCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.RoleV2.CreateRole(RoleFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourceV2RoleUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.RoleV2.UpdateRole(RoleFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourceV2RoleRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.RoleV2.GetRole(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}

	var spec role.CreateRole
	err = json.Unmarshal([]byte(resp.Spec), &spec)
	if err != nil {
		return
	}

	d.SetId(resp.ID)

	err = d.Set("name", resp.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", resp.Description)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("container_fqdn", spec.Spec.ContainerFQDN)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("image", spec.Spec.Image)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("repo_tag", spec.Spec.RepoTag)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("user_group", spec.Spec.UserGroup)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("email", spec.Spec.Email)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("device_ownership", spec.Spec.DeviceOwnership)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("platform", spec.Spec.Platform)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("known_device_only", spec.Spec.KnownDeviceOnly)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("mdm_present", spec.Spec.MDMPresent)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("serial_numbers", spec.Spec.SerialNumbers)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceV2RoleDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.RoleV2.DeleteRole(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return
}
