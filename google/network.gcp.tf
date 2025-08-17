module "project-gcp" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/project?ref=v40.0.0"
  name            = "musify-platform"

  project_reuse = {
    use_data_source = false
    project_attributes = {
      name   = "musify-platform"   
      number = "853148429083"
    }
  }

  iam = {   // IAP servizio Google: per collegarci alle macchine Google senza generare chiave
    "roles/iap.tunnelResourceAccessor" = [
      module.github-service-account.iam_email
    ],
    "roles/compute.instanceAdmin.v1" = [
      module.github-service-account.iam_email
    ]
  }

  services = [
    "container.googleapis.com",  # Necessario per GKE
    "compute.googleapis.com", # Necessario per GKE
    "iam.googleapis.com", # Necessario per permessi progetto cloud
    "serviceusage.googleapis.com" # Necessario per GKE
  ]
}

module "vpc-gcp" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-vpc?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  name       = "musify-platform-vpc"
  subnets = [
    {
      ip_cidr_range = "10.0.0.0/24"
      name          = "gke"
      region        = "europe-west12"
      secondary_ip_ranges = {
        pods     = "172.16.0.0/20"
        services = "192.168.0.0/24"
      }
    },
    {
      ip_cidr_range = "10.0.1.0/24"
      name          = "gke-cp"
      region        = "europe-west12"
    },
    {
      ip_cidr_range = "10.0.2.0/28"
      name          = "gke-bastion-host"
      region        = "europe-west12"
    }
  ]
}

module "addresses-gcp" {    // indirizzo globale per accesso al cluster
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-address?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  global_addresses = {
    gateway-ext-lb = {}
  }
}

module "github-service-account" {   
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/iam-service-account?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  name       = "github-deploy-sa"
  # non-authoritative roles granted *to* the service accounts on other resources
  iam_project_roles = {
    "${module.project-gcp.project_id}" = [
      "roles/container.clusterViewer"
    ]
  }
}

module "nat" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-cloudnat?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  name       = "musify-platform-nat"
  router_network = module.vpc-gcp.self_link
  region = "europe-west12"
}

module "bastion-service-account" {    // per fare tunneling verso GKE
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/iam-service-account?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  name       = "bastion-sa"
  # non-authoritative roles granted *to* the service accounts on other resources
  iam_project_roles = {
    "${module.project-gcp.project_id}" = [
      "roles/container.admin"
    ]
  }

  iam = {
    "roles/iam.serviceAccountUser" = [
      module.github-service-account.iam_email
    ]
  }
}

resource "google_compute_managed_ssl_certificate" "default" {
  name = "musify-platform-ssl-cert"

  project = module.project-gcp.project_id

  managed {
    domains = ["${module.addresses-gcp.global_addresses["gateway-ext-lb"].address}.nip.io"]   // "nip-io" traduce quello che ha prima in indirizzo IP
  }
}

module "firewall-gcp" {   // regole per fare comunicare cluster con le macchine intorno (bastion host) e IAP
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/net-vpc-firewall?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  network    = module.vpc-gcp.name
  egress_rules = {
    # Google possiede una allow-by-default in egress
  }
  ingress_rules = {
    # Google possiede una allow-by-default in ingress
    allow-ingress-bastion-from-iap = {
      description   = "Allow ingress from a specific tag."
      source_ranges = ["35.235.240.0/20"]
      destination_ranges = [ module.vpc-gcp.subnet_ips["europe-west12/gke-bastion-host"],module.vpc-gcp.subnet_ips["europe-west12/gke-cp"] ]
    }
    allow-ingress-gke-from-bastion = {
      description   = "Allow ingress from a specific tag."
      source_ranges = [ module.vpc-gcp.subnet_ips["europe-west12/gke-bastion-host"] ]
      destination_ranges = [ module.vpc-gcp.subnet_ips["europe-west12/gke-cp"] ]
    }
    allow-ingress-gke-from-gke-no = {
      description   = "Allow ingress from a specific tag."
      source_ranges = [ module.vpc-gcp.subnet_ips["europe-west12/gke"] ]
      destination_ranges = [ module.vpc-gcp.subnet_ips["europe-west12/gke-cp"] ]
    }
    deny-from-all = {
      deny = false
      description   = "Allow ingress from a specific tag."
      destination_ranges = [ "0.0.0.0/0" ]
    }
  }
}

# Da buttare giù (commentare anche questo)
# https://cloud.google.com/kubernetes-engine/docs/tutorials/private-cluster-bastion
module "bastion-host-vm" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/compute-vm?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  zone       = "europe-west12-b"

  instance_type = "e2-micro"
  name       = "gke-bastion-host"
  network_interfaces = [{
    network    = module.vpc-gcp.self_link
    subnetwork = module.vpc-gcp.subnet_self_links["europe-west12/gke-bastion-host"]
  }]

  service_account = {
    email = module.bastion-service-account.email
  }
}

# Da buttare giù (commentandola e dando "terraform apply")
module "cluster-gke" {
  source     = "git::https://github.com/GoogleCloudPlatform/cloud-foundation-fabric//modules/gke-cluster-standard?ref=v40.0.0"
  project_id = module.project-gcp.project_id
  
  name       = "musify-platform-gke"

  deletion_protection = false
  location   = "europe-west12"
  access_config = {
    ip_access = {
      private_endpoint_config = {
        endpoint_subnetwork = module.vpc-gcp.subnet_ids["europe-west12/gke-cp"]
        global_access       = false
      }
      authorized_ranges = {
        internal-vms = "10.0.2.0/28" # Solo la connettività dal bastion host può connettersi dal GKE
      }
    }
  }

  default_nodepool = {    // insieme di nodi creato con una certa caratteristica
    remove_pool = false
  }

  enable_features = {
    gateway_api = true
  }

  vpc_config = {
    network    = module.vpc-gcp.self_link
    subnetwork = module.vpc-gcp.subnet_self_links["europe-west12/gke"]
    secondary_range_names = {   // dice quale range name devono prendere i pod
      pods     = "pods"
      services = "services"
    }
  }
  labels = {
    environment = "dev"
  }
}   