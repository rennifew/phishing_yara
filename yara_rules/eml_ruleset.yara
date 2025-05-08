rule with_attachment {
  meta:
    description = "Обнаружение прикрепленного вложения к письму"

  strings:
    $attachment_id = "X-Attachment-Id"

  condition:
    $attachment_id
}

rule without_attachments {
  meta:
    description = "Обнаружение отсутствие каких-либо вложений."

  strings:
    $eml_01        = "From:"
    $eml_02        = "To:"
    $eml_03        = "Subject:"
    $attachment_id = "X-Attachment-Id"
    $mime_type     = "Content-Type: multipart/mixed"

  condition:
    all of ($eml_*) and
    not $attachment_id and
    not $mime_type
}

rule with_urls: mail {
  meta:
    description = "Обнаружение каких-либо ссылок в письме."

  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"

    $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

  condition:
    all of them
}

rule without_urls: mail {
  meta:
    description = "В письме отсутствуют какие-либо ссылки"

  strings:
    $eml_01 = "From:"
    $eml_02 = "To:"
    $eml_03 = "Subject:"

    $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/

  condition:
    all of ($eml_*) and
    not $url_regex
}
