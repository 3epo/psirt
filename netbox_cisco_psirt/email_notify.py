import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings

logger = logging.getLogger(__name__)


def get_smtp_config():
    return settings.PLUGINS_CONFIG.get('netbox_cisco_psirt', {})


def send_new_vulnerability_email(new_vulnerabilities):
    """
    Send an email notification about newly found vulnerabilities.
    new_vulnerabilities: list of Vulnerability model instances (newly created).
    """
    cfg = get_smtp_config()

    if not cfg.get('smtp_enabled', False):
        return

    smtp_host = cfg.get('smtp_host', '')
    smtp_port = int(cfg.get('smtp_port', 587))
    use_tls = cfg.get('smtp_use_tls', True)
    use_ssl = cfg.get('smtp_use_ssl', False)
    username = cfg.get('smtp_username', '')
    password = cfg.get('smtp_password', '')
    from_addr = cfg.get('smtp_from', username)
    to_raw = cfg.get('smtp_to', '')
    to_addrs = [a.strip() for a in to_raw.split(',') if a.strip()]

    if not smtp_host or not to_addrs:
        logger.warning("SMTP notification skipped: smtp_host or smtp_to not configured.")
        return

    subject = f"[NetBox PSIRT] {len(new_vulnerabilities)} new Cisco vulnerability(ies) found"

    # Build text and HTML bodies
    text_rows = ""
    html_rows = ""
    for vuln in new_vulnerabilities:
        advisory = vuln.advisory
        device = vuln.device
        platform = device.platform.name if device and device.platform else "N/A"
        
        text_rows += (
            f"- Device: {device}\n"
            f"  Platform: {platform}\n"
            f"  Advisory ID: {advisory.advisory_id} ({advisory.publication_url})\n"
            f"  Title: {advisory.title}\n"
            f"  Severity: {advisory.sir}\n"
            f"  CVSS: {advisory.cvss_base_score}\n\n"
        )
        
        html_rows += (
            f"<li>"
            f"<b>Device:</b> {device}<br>"
            f"<b>Platform:</b> {platform}<br>"
            f"<b>Advisory ID:</b> <a href='{advisory.publication_url}'>{advisory.advisory_id}</a><br>"
            f"<b>Title:</b> {advisory.title}<br>"
            f"<b>Severity:</b> {advisory.sir}<br>"
            f"<b>CVSS:</b> {advisory.cvss_base_score}"
            f"</li><br>"
        )

    plain_text = f"The following new Cisco PSIRT vulnerabilities were detected during the last sync:\n\n{text_rows}Log in to NetBox to review the full list of vulnerabilities."

    html_body = f"""
    <html><body>
    <p>The following <b>new</b> Cisco PSIRT vulnerabilities were detected during the last sync:</p>
    <ul>
{html_rows}
    </ul>
    <p>Log in to NetBox to review the full list of vulnerabilities.</p>
    </body></html>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = ', '.join(to_addrs)
    msg.attach(MIMEText(plain_text, 'plain'))
    msg.attach(MIMEText(html_body, 'html'))

    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            if use_tls:
                server.starttls()

        if username and password:
            server.login(username, password)

        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        logger.info(f"PSIRT email notification sent to: {', '.join(to_addrs)}")
    except Exception as e:
        logger.error(f"Failed to send PSIRT email notification: {e}")
