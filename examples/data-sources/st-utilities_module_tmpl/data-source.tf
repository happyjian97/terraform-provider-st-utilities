data "st-utilities_module_tmpl" "module_tmpl" {
  module_info = {
    brand        = "sige"
    env          = "basic"
    cloud        = "alicloud"
    app_category = "landing"
    region       = "cn-hongkong"
    region_iso   = "cn"
    zone         = "c"
  }
  module_tmpl = {
    vault_path = "devops/data/{brand}/{env}/{app_category}/{cloud}-{region}"
    resource_name = "{brand}-{env}-{app_category}-{region_iso}-{zone}"
    firebase_path = "{brand}/{env}/{app_category}/{cloud}-{region}/{zone}"
  }
}
