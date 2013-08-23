# Configures the ceilometer database
# This class will install the required libraries depending on the driver
# specified in the connection_string parameter
#
# == Parameters
#  [*database_connection*]
#    the connection string. format: [driver]://[user]:[password]@[host]/[database]
#
class ceilometer::db (
  $database_connection = 'mysql://ceilometer:ceilometer@localhost/ceilometer'
) {

  include ceilometer::params

  Package<| title == 'ceilometer-common' |> -> Class['ceilometer::db']

  validate_re($database_connection,
    '(sqlite|mysql|posgres|mongodb):\/\/(\S+:\S+@\S+\/\S+)?')

  case $database_connection {
    /^mysql:\/\//: {
      $backend_package = false
      include mysql::python
    }
    /^postgres:\/\//: {
      $backend_package = 'python-psycopg2'
    }
    /^mongodb:\/\//: {
      $backend_package = 'pymongo'
    }
    /^sqlite:\/\//: {
      $backend_package = 'python-pysqlite2'
    }
    default: {
      fail('Unsupported backend configured')
    }
  }

  if $backend_package and !defined(Package[$backend_package]) {
    package {'ceilometer-backend-package':
      ensure => present,
      name   => $backend_package,
    }
  }

  ceilometer_config {
    'DEFAULT/database_connection': value => $database_connection;
    #(H) 'database/connection': value => $database_connection;
  }

  Ceilometer_config['DEFAULT/database_connection'] ~> Exec['ceilometer-dbsync']
  #(H) Ceilometer_config['database/connection'] ~> Exec['ceilometer-dbsync']

  exec { 'ceilometer-dbsync':
    command     => $::ceilometer::params::dbsync_command,
    path        => '/usr/bin',
    user        => $::ceilometer::params::username,
    refreshonly => true,
    logoutput   => on_failure,
    subscribe   => Ceilometer_config['DEFAULT/database_connection']
    #(H) subscribe   => Ceilometer_config['database/connection']
  }

}