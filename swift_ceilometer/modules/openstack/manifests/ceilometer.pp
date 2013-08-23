
class openstack::ceilometer (
  # passwords/keys
  $auth_password,
  $rabbit_password,
  $db_password            = false,
  $metering_secret        = 'darksecret',

  # auth/keystone
  $auth_type              = 'keystone',
  $auth_host              = 'localhost',
  $auth_port              = '35357',
  $auth_admin_prefix      = false,
  $auth_tenant            = 'services',
  $auth_user              = 'ceilometer',
  $auth_protocol          = 'http',
  $auth_region            = 'RegionOne',

  # database/mysql
  $db_type                = 'mysql',
  $db_host                = '127.0.0.1',
  $db_name                = 'ceilometer',
  $db_user                = 'ceilometer',
  $sql_idle_timeout       = '3600',

  # amqp/rabbitmq 
  $rabbit_userid          = 'rabbit_user',
  $rabbit_host            = '127.0.0.1',
  $rabbit_hosts           = false,
  $rabbit_virtual_host    = '/',

  # general
  $bind_address           = '0.0.0.0',
  $verbose                = true,
  $debug                  = true,

  # enable services
  $enable_collector       = false,
  $enable_api             = false,
  $enable_central_agent   = false,
  $enable_compute_agent   = false,
) {
  ## Exec {
  ##   path => ['/usr/bin', '/bin', '/usr/sbin', '/sbin']
  ## }
  if $enable_collector or $enable_api {
    if ($db_type == 'mysql') {
      $sql_connection = "mysql://${db_user}:${db_password}@${db_host}/${db_name}?charset=utf8"
     
      # First, install a mysql server
      class { 'mysql::server': custom_setup_class => 'fake' }

      # And create the database
      class { 'ceilometer::db::mysql':
        password      => $db_password,
        dbname        => $db_name,
        user          => $db_user,
        allowed_hosts => [ '%', $::hostname ],
      }
    }
  if ($db_type == 'mongodb') {
    $sql_connection = "mongodb://${db_host}:27018/${db_name}"
  }
    # Configure the ceilometer database
    # Only needed if ceilometer::collector or ceilometer::api are declared
    class { 'ceilometer::db':
      database_connection => $sql_connection
    }
  }

  # Add the base ceilometer class & parameters
  # This class is required by ceilometer agents & api classes
  # The metering_secret parameter is mandatory
  class { '::ceilometer':
    metering_secret     => $metering_secret,
    rabbit_host         => $rabbit_host,
    rabbit_hosts        => $rabbit_hosts,
    rabbit_virtual_host => $rabbit_virtual_host,
    rabbit_userid       => $rabbit_userid,
    rabbit_password     => $rabbit_password,
    verbose             => $verbose,
    debug               => $debug,
  }

  if $enable_collector {
    # Install the collector service
    class { 'ceilometer::collector':
      #enabled => true,
    } 
  }

  if $enable_api {
    # Install the ceilometer-api service
    # The auth_password parameter is mandatory
    class { 'ceilometer::api':
      #enabled                    => true,
      keystone_host              => $auth_host,
      keystone_port              => $auth_port,
      keystone_auth_admin_prefix => $auth_admin_prefix,
      keystone_protocol          => $auth_protocol,
      keystone_user              => $auth_user,
      keystone_tenant            => $auth_tenant,
      keystone_password          => $auth_password,
      bind_host                  => $bind_address,
    }
  }

  # Configure authentication url
  $auth_url = "${auth_protocol}://${auth_host}:${auth_port}/v2.0"

  if $enable_central_agent {
    # Install central agent
    class { 'ceilometer::agent::central':
      auth_url         => $auth_url,
      auth_region      => $auth_region,
      auth_user        => $auth_user,
      auth_password    => $auth_password,
      auth_tenant_name => $auth_tenant,
      #auth_tenant_id   => '',
      #enabled          => true,
    }
  }

  if $enable_compute_agent {
    # Install compute agent
    class { 'ceilometer::agent::compute':
      auth_url         => $auth_url,
      auth_region      => $auth_region,
      auth_user        => $auth_user,
      auth_password    => $auth_password,
      auth_tenant_name => $auth_tenant,
      #auth_tenant_id   => '',
      #enabled          => true,
    }
  }

  # install client tools
  class { 'ceilometer::client':
  }
}

