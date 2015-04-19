<?php 
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;
use \Workerman\Autoloader;

// 自动加载类
require_once __DIR__ . '/../../Workerman/Autoloader.php';

Autoloader::setRootPath(__DIR__);

$METHOD = 'table';
$PASSWORD = 'workerman';

define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);


define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);


$worker = new Worker('tcp://0.0.0.0:1081');
$worker->count = 12;
if($METHOD == 'table')
{
    Encryptor::initTable($PASSWORD);
}
$worker->onConnect = function($connection)use($METHOD, $PASSWORD)
{
    $connection->stage = STAGE_INIT;
    $connection->encryptor = new Encryptor($PASSWORD, $METHOD);
};
$worker->onMessage = function($connection, $buffer)
{
    switch($connection->stage)
    {
        case STAGE_INIT:
        case STAGE_ADDR:
            $buffer = $connection->encryptor->decrypt($buffer);
            $header_data = parse_socket5_header($buffer);
            $header_len = $header_data[3];
            if(!$header_data)
            {
                $connection->close();
                return;
            }
            $remote_connection = new AsyncTcpConnection('tcp://'.$header_data[1].':'.$header_data[2]);
            $remote_connection->onBufferFull = function($remote_connection)use($connection)
            {
                $connection->pauseRecv();
            };
            $remote_connection->onBufferDrain = function($remote_connection)use($connection)
            {
                $connection->resumeRecv();
            };
            $remote_connection->onMessage = function($remote_connection, $buffer)use($connection)
            {
                $connection->send($connection->encryptor->encrypt($buffer));
            };
            $remote_connection->onClose = function($remote_connection)use($connection)
            {
                $connection->close();
            };
            $remote_connection->onError = function($remote_connection, $code, $type)use($connection)
            {
                $connection->close();
            };
            $connection->onBufferFull = function($connection)use($remote_connection)
            {
                $remote_connection->pauseRecv();
            };
            $connection->onBufferDrain = function($connection)use($remote_connection)
            {
                $remote_connection->resumeRecv();
            };
            $connection->onMessage = function($connection, $data)use($remote_connection)
            {
                $remote_connection->send($connection->encryptor->decrypt($data));
            };
            $connection->onClose = function($connection)use($remote_connection)
            {
                $remote_connection->close();
            };
            $connection->onError = function($connection, $code, $msg)use($remote_connection)
            {
                echo "connection err $code $msg\n";
                $connection->close();
                $remote_connection->close();
            };
            $remote_connection->connect();
            $connection->state = STAGE_STREAM;
            if(strlen($buffer) > $header_len)
            {
                $remote_connection->send(substr($buffer,$header_len));
            }
    }
};


function parse_socket5_header($buffer)
{
    $addr_type = ord($buffer[0]);
    switch($addr_type)
    {
        case ADDRTYPE_IPV4:
            $dest_addr = ord($buffer[1]).'.'.ord($buffer[2]).'.'.ord($buffer[3]).'.'.ord($buffer[4]);
            $port_data = unpack('n', substr($buffer, 5, 2));
            $dest_port = $port_data[1];
            $header_length = 7;
            break;
        case ADDRTYPE_HOST:
            $addrlen = ord($buffer[1]);
            $dest_addr = substr($buffer, 2, $addrlen);
            $port_data = unpack('n', substr($buffer, 2 + $addrlen, 2));
            $dest_port = $port_data[1];
            $header_length = $addrlen + 4;
            break;
       case ADDRTYPE_IPV6:
            echo "todo ipv6 not support yet\n";
            return false;
       default:
            echo "unsupported addrtype $addr_type\n";
            return false;
    }
    return array($addr_type, $dest_addr, $dest_port, $header_length);
}

// 如果不是在根目录启动，则运行runAll方法
if(!defined('GLOBAL_START'))
{
    Worker::runAll();
}
