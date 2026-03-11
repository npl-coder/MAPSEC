<?php
class DATABASE_CONFIG {

        public $default = array(
                'datasource' => 'Database/Mysql',
                'persistent' => false,
                'host' => 'mariadb',
                'login' => 'misp',
                'port' => 3306,
                'password' => 'misp_pass',
                'database' => 'misp',
                'prefix' => '',
                'encoding' => 'utf8',
        );
}
