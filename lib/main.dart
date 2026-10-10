
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from html import escape
import re

HOST = "127.0.0.1"
PORT = 8765

PAGE = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nyx WhatsApp Security</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: #101820;
    color: #f3f6f9;
    padding: 16px;
    max-width: 650px;
    margin: auto;
}
.card {
    background: #1d2a35;
    padding: 18px;
    border-radius: 14px;
    margin: 14px 0;
}
h1 { color: #42e8a5; font-size: 25px; }
input[type=text], textarea {
    width: 100%;
    box-sizing: border-box;
    padding: 12px;
    margin: 8px 0 14px;
    border-radius: 8px;
    border: 1px solid #526575;
    background: #101820;
    color: white;
    font-size: 16px;
}
.check { display: block; margin: 14px 0; line-height: 1.6; }
button, .btn {
    display: inline-block;
    background: #20c997;
    color: #071b16;
    padding: 12px 16px;
    border: 0;
    border-radius: 8px;
    font-weight: bold;
    font-size: 16px;
    text-decoration: none;
    cursor: pointer;
}
.note { color: #c3d0d9; line-height: 1.7; }
.result { border-right: 4px solid #20c997; padding: 10px; }
.warning { color: #ffcc80; }
</style>
</head>
<body>
<h1>Nyx WhatsApp Security</h1>
<p class="note">أداة محلية لفحص تنسيق الرقم وتقييم مؤشرات الاحتيال.</p>

<div class="card">
<form method="POST" action="/scan">
<label for="phone">رقم الهاتف مع مفتاح الدولة:</label>
<input id="phone" name="phone" type="text"
placeholder="+201012345678" required>

<h3>هل لاحظت أي سلوك من الآتي؟</h3>

<label class="check">
<input type="checkbox" name="otp">
طلب منك كود التحقق أو رمز تسجيل الدخول
</label>

<label class="check">
<input type="checkbox" name="link">
أرسل رابطًا مشبوهًا أو طلب فتح ملف مجهول
</label>

<label class="check">
<input type="checkbox" name="money">
طلب أموالًا أو بيانات بنكية بطريقة مريبة
</label>

<label class="check">
<input type="checkbox" name="impersonation">
انتحل شخصية شخص أو مؤسسة أخرى
</label>

<label class="check">
<input type="checkbox" name="threat">
أرسل تهديدات أو رسائل ابتزاز
</label>

<label for="notes">ملاحظات اختيارية (لا تكتب كلمات مرور أو أكواد تحقق):</label>
<textarea id="notes" name="notes" rows="3"
placeholder="اكتب وصفًا مختصرًا لما حدث"></textarea>

<button type="submit">افحص الرقم والمخاطر</button>
</form>
</div>

<div class="card">
<h3>حماية حسابك</h3>
<p class="note">
• لا تشارك كود التحقق مع أي شخص.<br>
• فعّل التحقق بخطوتين من إعدادات واتساب.<br>
• لا تفتح الروابط المشبوهة.<br>
• إذا وجدت مخالفة حقيقية، استخدم خيار الإبلاغ داخل واتساب.
</p>
</div>
</body>
</html>
"""


def make_result(phone, flags, notes):
    # تنظيف الرقم والتحقق من تنسيقه فقط
    cleaned = re.sub(r"[\s\-().]", "", phone)

    if cleaned.startswith("00"):
        cleaned = "+" + cleaned[2:]

    digits = cleaned[1:] if cleaned.startswith("+") else cleaned
    digits = re.sub(r"\D", "", digits)

    valid_format = (
        cleaned.startswith("+")
        and digits.isdigit()
        and 8 <= len(digits) <= 15
        and not digits.startswith("0")
    )

    score = 0
    reasons = []

    checks = [
        ("otp", 4, "طلب كود التحقق"),
        ("link", 3, "إرسال رابط مشبوه"),
        ("money", 3, "طلب أموال أو بيانات مالية"),
        ("impersonation", 4, "اشتباه في انتحال الشخصية"),
        ("threat", 4, "وجود تهديدات أو ابتزاز"),
    ]

    for key, points, description in checks:
        if key in flags:
            score += points
            reasons.append(description)

    score = min(score, 10)

    if score >= 7:
        level = "مؤشرات خطورة مرتفعة"
    elif score >= 4:
        level = "مؤشرات خطورة متوسطة"
    elif score > 0:
        level = "مؤشرات خطورة محدودة"
    else:
        level = "لا توجد مؤشرات محددة في إجاباتك"

    if valid_format:
        format_result = "تنسيق الرقم يبدو مقبولًا مبدئيًا."
    else:
        format_result = (
            "تعذر تأكيد التنسيق. استخدم + ثم مفتاح الدولة "
            "والرقم، وتحقق من عدد الأرقام."
        )

    reasons_html = "".join(
        "<li>" + escape(item) + "</li>" for item in reasons
    )
    if not reasons_html:
        reasons_html = "<li>لم يتم تحديد سلوك مريب في النموذج.</li>"

    notes_html = escape(notes.strip()) if notes.strip() else "لا توجد"

    return f"""
    <div class="card">
      <h2>نتيجة الفحص</h2>
      <div class="result">
        <p><b>الرقم المدخل:</b> {escape(phone)}</p>
        <p>{escape(format_result)}</p>
        <p><b>حالة التسجيل في واتساب:</b>
        لا يمكن تحديدها بهذه الأداة.</p>
        <p><b>تقييم السلوك:</b> {escape(level)}</p>
        <p><b>مؤشر المخاطر:</b> {score}/10</p>
      </div>
      <h3>المؤشرات التي حددتها</h3>
      <ul>{reasons_html}</ul>
      <p><b>ملاحظاتك:</b> {notes_html}</p>
      <p class="note">
      هذا التقييم مبني على إجاباتك فقط، وليس فحصًا حقيقيًا
      للحساب أو إثباتًا بأن صاحبه محتال.
      </p>
      <a class="btn" href="/">فحص رقم آخر</a>
    </div>
    <div class="card">
      <h3>كيف تبلغ عن مخالفة حقيقية؟</h3>
      <ol class="note">
        <li>افتح المحادثة في واتساب.</li>
        <li>اضغط على اسم جهة الاتصال أو الرقم.</li>
        <li>ابحث عن خيار الإبلاغ واتبع التعليمات الظاهرة.</li>
        <li>احتفظ بالأدلة ذات الصلة، ولا ترسل بلاغًا كاذبًا.</li>
      </ol>
    </div>
    """


class Handler(BaseHTTPRequestHandler):
    def send_page(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/":
            self.send_page("<h2>الصفحة غير موجودة</h2>", 404)
            return
        self.send_page(PAGE)

    def do_POST(self):
        if self.path != "/scan":
            self.send_page("<h2>الصفحة غير موجودة</h2>", 404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length > 12000:
            self.send_page("<h2>الطلب كبير جدًا</h2>", 413)
            return

        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw)

        phone = form.get("phone", [""])[0][:40]
        notes = form.get("notes", [""])[0][:500]

        if not phone.strip():
            self.send_page("<h2>أدخل رقم الهاتف أولًا</h2>", 400)
            return

        flags = {
            key for key in
            ("otp", "link", "money", "impersonation", "threat")
            if key in form
        }

        result = make_result(phone, flags, notes)
        self.send_page(PAGE + result)

    def log_message(self, fmt, *args):
        # لا نعرض تفاصيل الطلبات في سجل التشغيل
        pass


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print("Nyx WhatsApp Security Scanner")
    print("افتح المتصفح على: http://127.0.0.1:8765")
    print("لإيقاف الأداة اضغط Stop في Pydroid 3.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nتم إيقاف الأداة.")
    finally:
        server.server_close()
