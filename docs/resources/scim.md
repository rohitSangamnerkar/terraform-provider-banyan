---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "banyan_scim Resource - terraform-provider-banyan"
subcategory: ""
description: |-
  
---

# banyan_scim (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `base_url` (String) base url of idp
- `is_enabled` (Boolean) Is scim enabled for an org
- `token` (String, Sensitive) token is to communicate with idp
- `token_info` (Block Set, Max: 2) (see [below for nested schema](#nestedblock--token_info))

### Read-Only

- `id` (String) ID of the access tier group in Banyan

<a id="nestedblock--token_info"></a>
### Nested Schema for `token_info`

Optional:

- `created_at` (Number) time of token creation
- `uuid` (String) uuid of token
