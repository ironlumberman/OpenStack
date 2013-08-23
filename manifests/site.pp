#########################################################
#################!!! WARNING !!!#########################
##                                                     ##
##        Ceilometer required python-pecan             ##
##           on RHEL based OS                          ##
##          1. yum install python-pip                  ##
##          2. pythom-pip install pecan                ##
##                                                     ##
##                                                     ##
#########################################################
#########################################################

stage {'openstack-custom-repo': before => Stage['main']}
$mirror_type="default"
class { 'openstack::mirantis_repos': stage => 'openstack-custom-repo', type=>$mirror_type }
stage {'add_group': before => Stage['setup']}

exec {'add_group':
    path => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
    command => 'groupadd nova',
    unless => "grep nova /etc/group",
    }

##############################################
########## Define global variables ###########   
##############################################

$deployment_id = '48'
$ntp_servers = ['pool.ntp.org']
$swift_vip = '192.168.122.77'
$internal_virtual_ip = '192.168.122.88'
$ceilometer_vip = '192.168.122.88'
$public_interface = 'eth0'
$mongo_slave_ip = '192.168.122.46'
$mongo_arbiter_ip = '192.168.122.47'

$nodes_harr = [
  {
    'name' => 'swiftproxy-01',
    'role' => 'primary-swift-proxy',
    'role2' => 'haproxy',
    'internal_address' => '192.168.122.47',
    'public_address'   => '192.168.122.47',
    'haproxy_proxy'  =>  true,
    'ha_serv' => 'swift-proxy',
    'mongo_arbiter' => true,
    'p_keep' => 'master',
    'nagios_master' => true,
    'primary_proxy' => true,
  },
  {
    'name' => 'swiftproxy-02',
    'role' => 'swift-proxy',
    'internal_address' => '192.168.122.48',
    'public_address'   => '192.168.122.48',
    'ha_serv' => 'swift-proxy',
    'p_keep' => 'slave',
    'nagios_node' => true,
  },
  {
    'name' => 'swiftproxy-03',
    'role' => 'swift-proxy',
    'internal_address' => '192.168.122.49',
    'public_address'   => '192.168.122.49',
    'ha_serv' => 'swift-proxy',
    'p_keep' => 'slave2',
    'nagios_node' => true,
  },

 {
    'name' => 'ceilometer-01',
    'role' => 'ceilometer',
    'role2' => 'haproxy',
    'ha_serv' => 'ceilometer',
    'internal_address' => '192.168.122.45',
    'public_address'   => '192.168.122.45',
    'internal_interface' => 'eth0',
    'primary_controller' => true,
    'haproxy_ceilometer' => true,
    'master_ceilometer' => true,
    'mongo_master' => true,
    'public_interface' => 'eth0',
    'r_keep' => 'master',
    'nagios_node' => true,
  },

 {
    'name' => 'ceilometer-02',
    'role' => 'ceilometer',
    'role2' => 'haproxy',
    'ha_serv' => 'ceilometer',
    'internal_address' => '192.168.122.46',
    'public_address'   => '192.168.122.46',
    'slave_controller' => true,
    'haproxy_ceilometer' => true,
    'r_keep' => 'slave',
    'nagios_node' => true,
  },


  {
    'name' => 'swift-01',
    'role' => 'storage',
    'internal_address' => '192.168.122.50',
    'public_address'   => '192.168.122.50',
    'swift_zone'       => 1,
    'mountpoints'=> "1 2\n 2 1",
    'storage_local_net_ip' => '192.168.122.50',
  },
  {
    'name' => 'swift-02',
    'role' => 'storage',
    'internal_address' => '192.168.122.30',
    'public_address'   => '192.168.122.30',
    'swift_zone'       => 2,
    'mountpoints'=> "1 2\n 2 1",
    'storage_local_net_ip' => '192.168.122.30',
    'nagios_node' => true,
  },
  {
    'name' => 'swift-03',
    'role' => 'storage',
    'internal_address' => '192.168.122.31',
    'public_address'   => '192.168.122.31',
    'swift_zone'       => 3,
    'mountpoints'=> "1 2\n 2 1",
    'storage_local_net_ip' => '192.168.122.31',
    'nagios_node' => true,
  }
]


$nodes = $nodes_harr
$internal_netmask = '255.255.255.0'
$public_netmask = '255.255.255.0'

$nodeha = filter_nodes($nodes,'role2',$::hostname)

$node = filter_nodes($nodes,'name',$::hostname)
if empty($node) {
  fail("Node $::hostname is not defined in the hash structure")
}
$internal_address = $node[0]['internal_address']
$public_address = $node[0]['public_address']

$swift_local_net_ip      = $internal_address

if $node[0]['role'] == 'primary-swift-proxy' {
  $primary_proxy = true
} else {
  $primary_proxy = false
}

$master_swift_proxy_nodes = filter_nodes($nodes,'role','primary-swift-proxy')
$master_swift_proxy_ip = $master_swift_proxy_nodes[0]['internal_address']

$swift_proxy_nodes = merge_arrays(filter_nodes($nodes,'role','primary-swift-proxy'),filter_nodes($nodes,'role','swift-proxy'))
$swift_proxies = nodes_to_hash($swift_proxy_nodes,'name','internal_address')
$swift_nodes_ga = keys($swift_proxies)

$nv_physical_volume     = ['sdb','sdc']
$swift_loopback = false
$swift_user_password     = 'swift'

$verbose                = true
$admin_email          = 'vbakarinov@mirantis.com'
$keystone_db_password = 'keystone'
$keystone_db_user = 'keystone'
$keystone_admin_token = 'keystone_token'
$keystone_db_dbname      = 'keystone'
$admin_user           = 'admin'
$admin_password       = 'nova'

$swift_internal_addresses = $swift_proxies
$swift_proxy_hostnames = keys($swift_internal_addresses)

###################################################
################### END Define ####################
###################################################



Exec { logoutput => true, path => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'] }

class {'openstack::clocksync': ntp_servers=>$ntp_servers}

if !defined(Class['selinux']) and ($::osfamily == 'RedHat') {
  class { 'selinux':
    mode=>"disabled",
    stage=>"openstack-custom-repo"
  }
}

 exec {"iptables_stop":
        command => "/etc/init.d/iptables stop",
        path    => ["/usr/sbin","/sbin"],
}


 exec {"iptables_turn_off":
        command => "chkconfig iptables off",
        path    => ["/usr/sbin","/sbin"],
}


notify {" galera_node_address is  $internal_address,   galera_nodes  are   $swift_nodes_ga ":}


#################################################
############# Nodes section #####################
#################################################

node keystone inherits haproxy  {

class { 'keystone':
    admin_token  => $keystone_admin_token,
    bind_host    => $internal_address,
    verbose  => $verbose,
    debug    => $verbose,
    catalog_type => 'mysql',
    sql_connection => "mysql://${keystone_db_user}:${keystone_db_password}@${swift_vip}/${keystone_db_dbname}",
     require => Class["openstack::db::mysql"],
  }

  # set up keystone database
  # set up the keystone config for mysql
  class { 'openstack::db::mysql':
    keystone_db_password => $keystone_db_password,
    nova_db_password => $keystone_db_password,
    mysql_root_password => $keystone_db_password,
    cinder_db_password => $keystone_db_password,
    glance_db_password => $keystone_db_password,
    quantum_db_password => $keystone_db_password,
    mysql_bind_address => $internal_address,
    allowed_hosts => '%',
    custom_setup_class => 'galera',
    enabled                  => true,
    galera_node_address => $internal_address,
    galera_nodes => $swift_nodes_ga,
    primary_controller => $primary_proxy,
    galera_cluster_name => 'openstack',
  }
  # set up keystone admin users
  class { 'keystone::roles::admin':
    email    => $admin_email,
    password => $admin_password,
  }
  # configure the keystone service user and endpoint
  class { 'swift::keystone::auth':
    password => $swift_user_password,
    address  => $swift_vip,
  }
}

$hav_serv = $node[0]['ha_serv']

case $hav_serv {
 "ceilometer": {

$ceilometer_nodes = merge_arrays(filter_nodes($nodes,'role','ceilometer'),filter_nodes($nodes,'role','ceilometer'))
$ceilometer_ha = nodes_to_hash($ceilometer_nodes,'name','internal_address')
  Haproxy_service {
      balancers => $ceilometer_ha
    }
}

 "swift-proxy": {
    Haproxy_service {
      balancers => $swift_proxies
    }
}
 }

define haproxy_service($order, $balancers, $virtual_ips, $port, $ssl, $define_cookies = false, $define_backend = false) {
  case $name {
    "mysqld": {
      $haproxy_config_options = { 'option' => ['mysql-check user cluster_watcher', 'tcplog','clitcpka','srvtcpka'], 'balance' => 'roundrobin', 'mode' => 'tcp', 'timeout server' => '28801s', 'timeout client' => '28801s' }
      $balancermember_options = 'check inter 15s fastinter 2s downinter 1s rise 5 fall 3'
      $balancer_port = 3307
    }
    "rabbitmq-epmd": {
      $haproxy_config_options = { 'option' => ['clitcpka'], 'balance' => 'roundrobin', 'mode' => 'tcp'}
      $balancermember_options = 'check inter 5000 rise 2 fall 3'
      $balancer_port = 5673
    }
    "mongo": {
      $haproxy_config_options = { 'option' => ['clitcpka'], 'balance' => 'roundrobin', 'mode' => 'tcp'}
      $balancermember_options = 'check inter 5000 rise 2 fall 3'
      $balancer_port = 27018
    }
    "swift": {
      $haproxy_config_options = { 'option' => ['httplog'], 'balance' => 'roundrobin' }
      $balancermember_options = 'check'
      $balancer_port = $port

    }
    default: {
      $haproxy_config_options = { 'option' => ['httplog'], 'balance' => 'roundrobin' }
      $balancermember_options = 'check'
      $balancer_port = $port
    }
  }

  add_haproxy_service { $name :
    order                    => $order,
    balancers                => $balancers,
    virtual_ips              => $virtual_ips,
    port                     => $port,
    ssl                      => $ssl,
    haproxy_config_options   => $haproxy_config_options,
    balancer_port            => $balancer_port,
    balancermember_options   => $balancermember_options,
    define_cookies           => $define_cookies,
    define_backend           => $define_backend,
  }
}
define add_haproxy_service (
    $order,
    $balancers,
    $virtual_ips,
    $port,
    $ssl,
    $haproxy_config_options,
    $balancer_port,
    $balancermember_options,
    $mode = 'tcp',
    $define_cookies = false,
    $define_backend = false,
    $collect_exported = false
    ) {
    haproxy::listen { $name:
      order            => $order - 1,
      ipaddress        => $virtual_ips,
      ports            => $port,
      ssl              => $ssl,
      options          => $haproxy_config_options,
      collect_exported => $collect_exported,
      mode             => $mode,
    }
    @haproxy::balancermember { "${name}":
      order                  => $order,
      listening_service      => $name,
      balancers              => $balancers,
      balancer_port          => $balancer_port,
      balancermember_options => $balancermember_options,
      define_cookies         => $define_cookies,
      define_backend        =>  $define_backend,
    }
}
############################################
############  HAPROXY   ####################
############################################

node 'haproxy'  {

notify { "Applying $name class": }
sysctl::value { 'net.ipv4.ip_nonlocal_bind': value => '1' }


include  haproxy::params


    file { '/etc/rsyslog.d/haproxy.conf':
      ensure => present,
      content => 'local0.* -/var/log/haproxy.log'
    }

    class { 'haproxy':
      enable => true,
      global_options   => merge($::haproxy::params::global_options, {'log' => "/dev/log local0"}),
      defaults_options => merge($::haproxy::params::defaults_options, {'mode' => 'http'}),
      require => Sysctl::Value['net.ipv4.ip_nonlocal_bind'],
    }
 }
    $public_vrid   = $::deployment_id
    $internal_vrid = $::deployment_id + 1

$mongo_arbiter = $node[0]['mongo_arbiter']
$mongo_master = $node[0]['mongo_master']
$r_keep = $node[0]['r_keep']
$p_keep = $node[0]['p_keep']

case $r_keep {

  "master": {
   keepalived::instance { $internal_vrid:
      interface => 'eth0',
      virtual_ips => [$internal_virtual_ip],
      state    =>   'MASTER',
      priority =>  101,
       } 

          }

 "slave": {

    keepalived::instance { $internal_vrid:
      interface => 'eth0',
      virtual_ips => [$internal_virtual_ip],
      state    =>   'SLAVE',
      priority =>  100,
    }    
 }

 "default": {}
}

$master_ceilometer = $node[0]['master_ceilometer']

############################################
############  CEILOMETER   #################
############################################

node /ceilometer-[\d+]/ inherits haproxy {

 include stdlib
  class { 'operatingsystem::checksupported':
      stage => 'setup'
  }

class {'openstack::ceilometer':
  enable_api => true,
  enable_central_agent => true,
  enable_collector => true,
  enable_compute_agent => false,
  db_type => 'mongodb',
  db_host => $ceilometer_vip,
  db_name => 'ceilometer',
  auth_host => '192.168.122.77',
  auth_admin_prefix => false,
  auth_password => 'ceilometer',
  auth_port => '5000',
  auth_protocol => 'http',
  auth_region => 'RegionOne',
  auth_tenant => 'services',
  auth_user => 'ceilometer',
  loglevel => 'debug',
  metering_secret => 'secretsecret',
  rabbit_host => $ceilometer_vip,
  rabbit_password => 'nova',
  rabbit_userid => 'nova',
  rabbit_hosts  => $ceilometer_vip
}

$ceilometer_nodes = filter_nodes($nodes,'role','ceilometer')
$ceilometer_ha = nodes_to_hash($ceilometer_nodes,'name','internal_address')

haproxy_service { 'rabbitmq-epmd':    order => 91, port => 5672, ssl => "", virtual_ips => [$internal_virtual_ip], define_backend => true }
haproxy_service { 'mongo':    order => 70, port => 27018, ssl => "", virtual_ips => [$internal_virtual_ip], define_backend => true }

 notify { "Applying $name class": }

        class {'::mongodb':}
        mongodb::mongod {
            "mongod_instance":
                mongod_instance => "mongodb1",
                mongod_port => '27018',
                mongod_replSet => "MongoCluster01",
                mongod_add_options => ['slowms = 50']
        }

   ::logrotate::rule { 'mongodb': path => '/var/log/mongo/*.log', rotate => 5, rotate_every => 'day', compress => true,}

notify {" I am  $master_ceilometer":}

if $mongo_master {

  exec {"initiate":
        command => "mongo --port 27018 admin --eval \"printjson(rs.initiate({\\\"_id\\\": \\\"mongoCluster1\\\", \\\"members\\\":[{_id: 0,host:\\\"$mongo_slave_ip:27018\\\"}]}))\" >> /root/mongo",
        path    => ["/usr/bin","/bin"],
        require => Class["::mongodb"],
                                           }
#  exec {"wait":
#        command => "sleep 30",
#        path    => ["/usr/bin","/bin"],
#        require => Exec["initiate"],
#                                         }

  exec {"initiate2":
        command => "mongo --port 27018 admin --eval \"printjson(rs.initiate({\\\"_id\\\": \\\"mongoCluster1\\\", \\\"members\\\":[{_id: 0,host:\\\"$mongo_arbiter_ip:27018, true\\\"}]}))\" >> /root/mongo",
        path    => ["/usr/bin","/bin"],
        require => Class["::mongodb"],
                                           }

#  exec {"wait2":
#        command => "sleep 30",
#        path    => ["/usr/bin","/bin"],
#        require => Exec["initiate"],
#                                         }
}
  
$rabbit_password         = 'nova'
$rabbit_user             = 'nova'
$version = '2.8.7-2.el6'
$rabbit_port             = '5673'
$env_config =''

class { 'rabbitmq':
  config_cluster         => true,
  config_mirrored_queues => true,
  cluster_nodes          => ['ceilometer-01', 'ceilometer-02'],
  default_user           => $rabbit_user,
  default_pass           => $rabbit_password,
  port                   => $rabbit_port
}

 if $master_ceilometer {   
 
 exec { 'delete-public-virtual-ip':
  command => "ip a d ${ceilometer_vip} dev ${public_interface} label",
        unless  => "ip addr show dev ${public_interface} | grep -w ${ceilometer_vip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      }
->

 exec { 'create-public-virtual-ip':
  command => "ip addr add ${ceilometer_vip} dev ${public_interface} label",
        unless  => "ip addr show dev ${public_interface} | grep -w ${ceilometer_vip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      }

}

class {keepalived:}

}

###########################################
########   SWIFT - PROXY   ################
###########################################


node /swiftproxy-[\d+]/ inherits keystone {


class  {'::ceilometer::keystone::auth':

  password           => 'ceilometer',
  email              => 'ceilometer@localhost',
  auth_name          => 'ceilometer',
  service_type       => 'metering',
  public_address     => $ceilometer_ha,
  admin_address      => $ceilometer_ha,
  internal_address   => $ceilometer_ha,
  port               => '8777',
  region             => 'RegionOne',
  tenant             => 'services',
  api_protocol    => 'http',
  configure_endpoint => true
}

    haproxy_service { 'keystone-1': order => 20, port => 35357, ssl => "", virtual_ips => [$swift_vip]  }
    haproxy_service { 'keystone-2': order => 30, port => 5000, ssl => "", virtual_ips => [$swift_vip]  }
    haproxy_service { 'mysqld': order => 95, port => 3306, ssl => "", virtual_ips => [$swift_vip], define_backend => true }
    haproxy_service { 'swift': order => 96, port => 8080, ssl => "ssl crt /etc/haproxy/cert.pem\n  reqadd X-Forwarded-Proto:\ https", virtual_ips => [$swift_vip], balancers => $swift_proxies }

file { 'cert.pem':
        path    => '/etc/haproxy/cert.pem',
        ensure  => file,
        require => Package['haproxy'],
        content => template("haproxy/cert.pem.erb"),
      }

  include stdlib
  class { 'operatingsystem::checksupported':
      stage => 'setup'
  }
 
  if $primary_proxy {
    ring_devices {'all':
      storages => filter_nodes($nodes, 'role', 'storage')
    }
  }
  class { 'openstack::swift::proxy':
    swift_user_password     => $swift_user_password,
    swift_proxies           => $swift_proxies,
    primary_proxy           => $primary_proxy,
    controller_node_address => $internal_address,
    swift_local_net_ip      => $internal_address,
    master_swift_proxy_ip   => $internal_address,
  }

package { 'socat': ensure => present }

    exec { 'wait-for-haproxy-mysql-backend':
      command   => "echo show stat | socat unix-connect:///var/lib/haproxy/stats stdio | grep -q '^mysqld,BACKEND,.*,UP,'",
      path      => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      try_sleep => 5,
      tries     => 60,
    }

    Exec<| title == 'wait-for-synced-state' |> -> Exec['wait-for-haproxy-mysql-backend']
    Exec['wait-for-haproxy-mysql-backend'] -> Exec<| title == 'initial-db-sync' |>
    Exec['wait-for-haproxy-mysql-backend'] -> Exec<| title == 'keystone-manage db_sync' |>


   Class['haproxy'] -> Class['galera']

if $mongo_arbiter    {  

       class {'::mongodb':}
        mongodb::mongod {
            "mongod_instance":
                mongod_instance => "mongodb1",
                mongod_port => '27018',
                mongod_replSet => "MongoCluster01",
                mongod_add_options => ['slowms = 50']
        }

   ::logrotate::rule { 'mongodb': path => '/var/log/mongo/*.log', rotate => 5, rotate_every => 'day', compress => true,}
}

 if $master_ceilometer {

 exec { 'delete-public-virtual-ip':
  command => "ip a d ${ceilometer_vip} dev ${public_interface} label",
        unless  => "ip addr show dev ${public_interface} | grep -w ${ceilometer_vip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      }
->

 exec { 'create-public-virtual-ip':
  command => "ip addr add ${ceilometer_vip} dev ${public_interface} label",
        unless  => "ip addr show dev ${public_interface} | grep -w ${ceilometer_vip}",
        path    => ['/usr/bin', '/usr/sbin', '/sbin', '/bin'],
      }
}

case $p_keep {

  "master": {
   keepalived::instance { $internal_vrid:
      interface => 'eth0',
      virtual_ips => [$swift_vip],
      state    =>   'MASTER',
      priority =>  101,
       }
          }

 "slave": {

    keepalived::instance { $internal_vrid:
      interface => 'eth0',
      virtual_ips => [$swift_vip],
      state    =>   'SLAVE',
      priority =>  100,
    }
 }

 "slave2": {

    keepalived::instance { $internal_vrid:
      interface => 'eth0',
      virtual_ips => [$swift_vip],
      state    =>   'SLAVE',
      priority =>  101,
    }
 }

 "default": {}
}

class {keepalived:}

}


node /swift-[\d+]/ {

  include stdlib
  class { 'operatingsystem::checksupported':
      stage => 'setup'
  }

  $swift_zone = $node[0]['swift_zone']
 notice("swift zone is: ${swift_zone}")

  class { 'openstack::swift::storage_node':
    swift_zone             => $swift_zone,
    swift_local_net_ip     => $swift_local_net_ip,
    master_swift_proxy_ip  => $master_swift_proxy_ip,
    storage_devices        => $nv_physical_volume,
    storage_base_dir       => '/dev',
    db_host                => $swift_vip,
    service_endpoint       => $swift_vip,
    cinder                 => false
  }

}

$nagios_master = $node[0]['nagios_master']
$nagios_node = $node[0]['nagios_node']
$mysql_pass = nova


