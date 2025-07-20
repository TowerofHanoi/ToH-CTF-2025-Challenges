<?php
session_start();

if (isset($_GET['lang'])) {
  $lang = $_GET['lang'];
  // we don't trust the GET parameter, comes from the user
  if ($lang != 'en' && $lang != 'it') {
    // default if lang is not valid, is italian
    $lang = 'it';
  }
  // Register the session and set the cookie
  $_SESSION['lang'] = $lang;
  setcookie('lang', $lang, time() + (3600 * 24 * 30));
} else if (isset($_SESSION['lang'])) {
  $lang = $_SESSION['lang'];
} else if (isset($_COOKIE['lang'])) {
  // cookie is safe, we set it ourself
  $lang = $_COOKIE['lang'];
} else {
  // default language is browser language
  $lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
  if ($lang != 'en' && $lang != 'it') {
    // default if browser is not valid, is italian
    $lang = 'it';
  }
}

// include the language file
include 'lang/' . $lang . '.php';
?>