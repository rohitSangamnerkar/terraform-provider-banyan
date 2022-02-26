---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "banyan_policy_attachment Resource - terraform-provider-banyan"
subcategory: ""
description: |-
  A Banyan policy attachment. Attaches a policy.
---

# banyan_policy_attachment (Resource)

A Banyan policy attachment. Attaches a policy.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **attached_to_id** (String) ID of the resource the policy will be attached to
- **attached_to_type** (String) Type which the policy is attached to (i.e. service / saasapp)
- **is_enforcing** (Boolean) Sets whether the policy is enforcing or not
- **policy_id** (String) Name of the policy

### Optional

- **id** (String) The ID of this resource.

