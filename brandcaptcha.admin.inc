<?php

/**
 * @file
 * Provides the BrandCaptcha administration settings.
 */

/**
 * Form callback; administrative settings for BrandCaptcha.
 */
function brandcaptcha_admin_settings() {
  $form['brandcaptcha_general_settings'] = array(
    '#type' => 'fieldset',
    '#title' => t('General settings'),
  );
  $form['brandcaptcha_general_settings']['brandcaptcha_public_key'] = array(
    '#type' => 'textfield',
    '#title' => t('Public key'),
    '#default_value' => variable_get('brandcaptcha_public_key', ''),
    '#maxlength' => 40,
    '#description' => t('The public key given to you when you <a href="@url">register for BrandCaptcha</a>.', array('@url' => 'http://panel.pontamedia.net')),
    '#required' => TRUE,
  );
  $form['brandcaptcha_general_settings']['brandcaptcha_private_key'] = array(
    '#type' => 'textfield',
    '#title' => t('Private key'),
    '#default_value' => variable_get('brandcaptcha_private_key', ''),
    '#maxlength' => 40,
    '#description' => t('The private key given to you when you <a href="@url">register for BrandCaptcha</a>.', array('@url' => 'http://panel.pontamedia.net')),
    '#required' => TRUE,
  );
  $form['brandcaptcha_general_settings']['brandcaptcha_lang'] = array(
    '#type' => 'select',
    '#title' => t('Language'),
    '#description' => t('Language in which you want to display BrandCAPTCHA’S box texts (e.g. “Your Answer”, “Reload”, etc.).'),
    '#options' => array(
      'es' => t('Español'),
      'en' => t('Ingles'),
      'pt' => t('Portugués'),
    ),
    '#default_value' => variable_get('brandcaptcha_lang', 'es'),
  );

  return system_settings_form($form);
}