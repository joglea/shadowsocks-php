<?php 
use \Workerman\Worker;
use \Workerman\WebServer;
use \Workerman\Connection\TcpConnection;
use \Workerman\Connection\AsyncTcpConnection;
use \Workerman\Autoloader;

// 自动加载类
require_once __DIR__ . '/../../Workerman/Autoloader.php';
require_once __DIR__.'/config.php';
Autoloader::setRootPath(__DIR__);

// 状态相关
define('STAGE_INIT', 0);
define('STAGE_ADDR', 1);
define('STAGE_UDP_ASSOC', 2);
define('STAGE_DNS', 3);
define('STAGE_CONNECTING', 4);
define('STAGE_STREAM', 5);
define('STAGE_DESTROYED', -1);

// 命令
define('CMD_CONNECT', 1);
define('CMD_BIND', 2);
define('CMD_UDP_ASSOCIATE', 3);

// 请求地址类型
define('ADDRTYPE_IPV4', 1);
define('ADDRTYPE_IPV6', 4);
define('ADDRTYPE_HOST', 3);

// 初始化worker，监听$PORT端口
$worker = new Worker('tcp://0.0.0.0:'.$PORT);
// 进程数量
$worker->count = $PROCESS_COUNT;
// 如果加密算法为table，初始化table
if($METHOD == 'table')
{
    Encryptor::initTable($PASSWORD);
}
// 当shadowsocks客户端连上来时
$worker->onConnect = function($connection)use($METHOD, $PASSWORD)
{
    // 设置当前连接的状态为STAGE_INIT，初始状态
    $connection->stage = STAGE_INIT;
    // 初始化加密类
    $connection->encryptor = new Encryptor($PASSWORD, $METHOD);
};

// 当shadowsocks客户端发来消息时
$worker->onMessage = function($connection, $buffer)
{
    // 判断当前连接的状态
    switch($connection->stage)
    {
        // 如果不是STAGE_STREAM，则尝试解析实际的请求地址及端口
        case STAGE_INIT:
        case STAGE_ADDR:
            // 先解密数据
            $buffer = $connection->encryptor->decrypt($buffer);
            // 解析socket5头
            $header_data = parse_socket5_header($buffer);
            // 头部长度
            $header_len = $header_data[3];
            // 解析头部出错，则关闭连接
            if(!$header_data)
            {
                $connection->close();
                return;
            }
            // 解析得到实际请求地址及端口
            $host = $header_data[1];
            $port = $header_data[2];
            $address = "tcp://$host:$port";
            // 异步建立与实际服务器的远程连接
            $remote_connection = new AsyncTcpConnection($address);
            // 远程连接的发送缓冲区满，则停止读取shadowsocks客户端发来的数据
            $remote_connection->onBufferFull = function($remote_connection)use($connection)
            {
                $connection->pauseRecv();
            };
            // 远程连接的发送缓冲区发送完毕后，则恢复读取shadowsocks客户端发来的数据
            $remote_connection->onBufferDrain = function($remote_connection)use($connection)
            {
                $connection->resumeRecv();
            };
            // 远程连接发来消息时，进行加密，转发给shadowsocks客户端，shadowsocks客户端会解密转发给浏览器
            $remote_connection->onMessage = function($remote_connection, $buffer)use($connection)
            {
                $connection->send($connection->encryptor->encrypt($buffer));
            };
            // 远程连接断开时，则断开shadowsocks客户端的连接
            $remote_connection->onClose = function($remote_connection)use($connection)
            {
                $connection->close();
            };
            // 远程连接发生错误时（一般是建立连接失败错误），关闭shadowsocks客户端的连接
            $remote_connection->onError = function($remote_connection, $code, $msg)use($connection, $address)
            {
                echo "remote_connection $address error code:$code msg:$msg\n";
                $connection->close();
            };
            // shadowsocks客户端的连接发送缓冲区满时，则停止读取远程服务端的数据
            $connection->onBufferFull = function($connection)use($remote_connection)
            {
                $remote_connection->pauseRecv();
            };
            // 当shadowsocks客户端的连接发送缓冲区发送完毕后，继续读取远程服务端的数据
            $connection->onBufferDrain = function($connection)use($remote_connection)
            {
                $remote_connection->resumeRecv();
            };
            // 当shadowsocks客户端发来数据时，解密数据，并发给远程服务端
            $connection->onMessage = function($connection, $data)use($remote_connection)
            {
                $remote_connection->send($connection->encryptor->decrypt($data));
            };
            // 当shadowsocks客户端关闭连接时，关闭远程服务端的连接
            $connection->onClose = function($connection)use($remote_connection)
            {
                $remote_connection->close();
            };
            // 当shadowsocks客户端连接上有错误时，关闭远程服务端连接
            $connection->onError = function($connection, $code, $msg)use($remote_connection)
            {
                echo "connection err code:$code msg:$msg\n";
                $connection->close();
                $remote_connection->close();
            };
            // 执行远程连接
            $remote_connection->connect();
            // 改变当前连接的状态为STAGE_STREAM，即开始转发数据流
            $connection->state = STAGE_STREAM;
            // shadowsocks客户端第一次发来的数据超过头部，则要把头部后面的数据发给远程服务端
            if(strlen($buffer) > $header_len)
            {
                $remote_connection->send(substr($buffer,$header_len));
            }
    }
};

/**
 * 解析shadowsocks客户端发来的socket5头部数据
 * @param string $buffer
 */
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
