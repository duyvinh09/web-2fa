<?php
require_once 'GoogleAuthenticator.php';

function removeSpaces($str) {
    return str_replace(' ', '', $str);
}

if (isset($_GET['key'])) {
    $key = trim($_GET['key']);
    $key = removeSpaces($key);

    if (htmlspecialchars($key, ENT_QUOTES, 'UTF-8') !== $key) {
        $error_response = array(
            "status" => "error",
            "result" => array(
                "message" => "Chuỗi nhập chứa ký tự đặc biệt. Vui lòng nhập lại."
            ),
            "Admin" => array(
                "Author" => "Đinh Duy Vinh",
                "Facebook" => "https://www.facebook.com/duyvinh09",
                "Zalo" => "https://zalo.me/duyvinh09"
            )
        );

        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($error_response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    $ga = new PHPGangsta_GoogleAuthenticator();
    $code = $ga->getCode($key);
    
    if (!empty($key)) {
        $response = array(
            "status" => "success",
            "code" => $code,
            "Admin" => array(
                "Author" => "Đinh Duy Vinh",
                "Facebook" => "https://www.facebook.com/duyvinh09",
                "Zalo" => "https://zalo.me/duyvinh09"
            )
        );
        
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } else {
        $error_response = array(
            "status" => "error",
            "result" => array(
                "message" => "Thiếu tham số. Vui lòng nhập Mã 2 yếu tố.",
                "type" => "?key={key}"
            ),
            "Admin" => array(
                "Author" => "Đinh Duy Vinh",
                "Facebook" => "https://www.facebook.com/duyvinh09",
                "Zalo" => "https://zalo.me/duyvinh09"
            )
        );
        
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode($error_response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
?>