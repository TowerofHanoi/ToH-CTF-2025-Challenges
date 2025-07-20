<?php
include 'lang.php';

$rsvp_path = getenv("RSVP_PATH");

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header('Content-Type: text/plain');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(200);
  exit();
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  http_response_code(405);
  exit('Method Not Allowed');
}

if (!isset($_POST['name']) || !isset($_POST['email']) || !isset($_POST['guestsnumber'])) {
  http_response_code(400);
  exit('Bad Request');
}

$name = $_POST['name'];
$email = $_POST['email'];
$guestsnumber = $_POST['guestsnumber'];

// Validate & sanitize data
if (!empty($name) && !empty($email) && !empty($guestsnumber)) {
  // Get data from POST
  // checks on guestsnumber and name length (maximum 50 characters)
  if ($guestsnumber >= 0 && $guestsnumber <= 99) {
    // Prepare data and sanitize (name must be only string of a-zA-Z or spaces or '.)
    $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    $name = preg_replace('/[^a-zA-Z \'\.]/', '', $name);
    if (strlen($name) > 100) {
      http_response_code(400);
      echo $i18n['Invalid name'];
      exit();
    }
    $email = preg_replace('/[^a-zA-Z0-9@\.\_\-]/', '', $email);
    $guests_number = preg_replace('/[^0-9]/', '', $guestsnumber);
    // Prepare data for file
    if (!empty($name) && !empty($email) && !empty($guestsnumber)) {
      $data = $name . ',' . $email . ',' . $guestsnumber . PHP_EOL;
      // Write data to file
      
      // file_put_contents($rsvp_path, $data, FILE_APPEND); // we don't really need your RSVP :P
      echo $i18n['RSVP.success'];
      exit();
    }
    http_response_code(400);
    echo $i18n['Invalid data'];
    exit();
  }
} else {
  // Set response's header to 400 Bad Request
  http_response_code(400);
  echo $i18n['Missing data'];
}
?>