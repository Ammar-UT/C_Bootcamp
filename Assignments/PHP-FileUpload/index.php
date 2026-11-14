<?php
/**
 * ============================================================================
 * التكليف الثاني عشر: نظام رفع الملفات الآمن والتحقق متعدد الطبقات
 * Assignment 12: Secure File Upload System & Multi-Layer Verification
 * Cyber Security Bootcamp - PHP & Web Track
 * ============================================================================
 * 
 * استراتيجية الدفاع في العمق (Defense-in-Depth):
 * 1. فحص وجود أخطاء في الرفع عبر $_FILES['uploaded_file']['error'].
 * 2. التحقق من حجم الملف وضمان عدم تجاوزه الحد الأقصى المسموح (2MB).
 * 3. استخراج الامتداد وفحصه عبر قائمة مسموحات صارمة (Whitelist).
 * 4. فحص محتوى الملف الفعلي (MIME Type) باستخدام مكتبة Fileinfo (finfo_file).
 * 5. توليد اسم عشوائي آمن تشفيرياً باستخدام bin2hex(random_bytes(16)).
 * 6. نقل الملف إلى مجلد التخزين المخصص عبر move_uploaded_file() وضبط الصلاحيات.
 * ============================================================================
 */

declare(strict_types=1);

// --- إعدادات وثوابت النظام (Configuration Constants) ---
const UPLOAD_DIR       = __DIR__ . '/uploads';
const MAX_FILE_SIZE    = 2 * 1024 * 1024; // 2 Megabytes (2MB)

// قائمة الامتدادات المسموح بها مع أنواع الـ MIME المتطابقة معها
// Extension whitelist mapped to expected genuine MIME types
const ALLOWED_EXTENSIONS_MAP = [
    'jpg'  => ['image/jpeg'],
    'jpeg' => ['image/jpeg'],
    'png'  => ['image/png'],
    'pdf'  => ['application/pdf'],
];

// المتغيرات الخاصة بالاستجابة ورسائل التنبيه
$statusMessage = null;
$statusType    = null; // 'success' or 'danger'
$debugDetails  = [];

/**
 * تجهيز مجلد التخزين وتأمينه بملف .htaccess لمنع تنفيذ السكربتات
 */
function initializeUploadDirectory(string $dir): void {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    // تأمين المجلد ضد تنفيذ السكربتات الخبيثة (Defense-in-Depth)
    $htaccessFile = $dir . '/.htaccess';
    if (!file_exists($htaccessFile)) {
        $htaccessContent = <<<HTACCESS
# منع تشغيل ملفات PHP وأي سكربتات تنفيذية داخل مجلد المرفوعات
<IfModule mod_authz_core.c>
    <FilesMatch "\.(php|phtml|php3|php4|php5|phps|phar|inc|pl|py|cgi|sh)$">
        Require all denied
    </FilesMatch>
</IfModule>
<IfModule !mod_authz_core.c>
    <FilesMatch "\.(php|phtml|php3|php4|php5|phps|phar|inc|pl|py|cgi|sh)$">
        Order Deny,Allow
        Deny from all
    </FilesMatch>
</IfModule>
Options -Indexes -ExecCGI
HTACCESS;
        file_put_contents($htaccessFile, $htaccessContent);
    }
}

/**
 * دالة المعالجة الرئيسية للتحقق من الملف ورفعه وفق استراتيجية الدفاع في العمق
 *
 * @param array $fileData مصفوفة الملف القادمة من $_FILES['uploaded_file']
 * @return array مصفوفة تحتوي على النتيجة (success/error)، الرسالة، وتفاصيل التحقق
 */
function handleSecureUpload(array $fileData): array {
    // 0. التحقق من تجهيز مجلد التخزين
    initializeUploadDirectory(UPLOAD_DIR);

    $originalName = (string)($fileData['name'] ?? '');
    $tmpFilePath  = (string)($fileData['tmp_name'] ?? '');
    $fileError    = (int)($fileData['error'] ?? UPLOAD_ERR_NO_FILE);
    $fileSize     = (int)($fileData['size'] ?? 0);

    // 1. فحص كود خطأ الرفع الأساسي في PHP
    if ($fileError !== UPLOAD_ERR_OK) {
        $errorMessages = [
            UPLOAD_ERR_INI_SIZE   => 'حجم الملف يتجاوز الحد المسموح في إعدادات الخادم (upload_max_filesize).',
            UPLOAD_ERR_FORM_SIZE  => 'حجم الملف يتجاوز الحد المحدد في نموذج الإرسال.',
            UPLOAD_ERR_PARTIAL    => 'تم رفع جزء من الملف فقط ولم يكتمل الرفع.',
            UPLOAD_ERR_NO_FILE    => 'لم يتم اختيار أي ملف للرفع.',
            UPLOAD_ERR_NO_TMP_DIR => 'مجلد الملفات المؤقتة غير موجود في الخادم.',
            UPLOAD_ERR_CANT_WRITE => 'فشل الخادم في حفظ الملف على القرص.',
            UPLOAD_ERR_EXTENSION  => 'تم إيقاف رفع الملف بواسطة إضافة برمجية في الخادم.',
        ];
        return [
            'success' => false,
            'message' => $errorMessages[$fileError] ?? 'حدث خطأ غير معروف أثناء رفع الملف.',
            'details' => ['ErrorCode' => $fileError]
        ];
    }

    // التحقق من أن الملف رُفع فعلياً عبر بروتوكول HTTP POST ومن وجود المسار المؤقت
    if (!is_uploaded_file($tmpFilePath)) {
        return [
            'success' => false,
            'message' => 'تنبيه أمني: محاولة رفع غير مصرح بها أو مسار مؤقت غير صالح.',
            'details' => ['Error' => 'Invalid temporary file path']
        ];
    }

    // 2. فحص الحجم الأقصى المسموح (File Size Validation)
    if ($fileSize <= 0) {
        return [
            'success' => false,
            'message' => 'الملف المرفوع فارغ (0 بايت).',
            'details' => ['FileSize' => '0 Bytes']
        ];
    }

    if ($fileSize > MAX_FILE_SIZE) {
        return [
            'success' => false,
            'message' => sprintf(
                'حجم الملف (%s كيلوبايت) يتجاوز الحد الأقصى المسموح به وهو (%s ميجابايت).',
                round($fileSize / 1024, 2),
                MAX_FILE_SIZE / (1024 * 1024)
            ),
            'details' => [
                'FileSize'    => $fileSize . ' bytes',
                'MaxAllowed'  => MAX_FILE_SIZE . ' bytes'
            ]
        ];
    }

    // 3. التحقق من امتداد الملف عبر القائمة البيضاء (Extension Whitelist Validation)
    // استخدام pathinfo لاستخراج الامتداد بدقة وتحويله إلى أحرف صغيرة لمنع تجاوز الفحص
    $fileExtension = strtolower((string)pathinfo($originalName, PATHINFO_EXTENSION));

    if (!array_key_exists($fileExtension, ALLOWED_EXTENSIONS_MAP)) {
        return [
            'success' => false,
            'message' => sprintf('امتداد الملف (.%s) غير مسموح به! الامتدادات المسموحة فقط هي: [%s]',
                htmlspecialchars($fileExtension),
                implode(', ', array_keys(ALLOWED_EXTENSIONS_MAP))
            ),
            'details' => [
                'OriginalFilename'  => $originalName,
                'DetectedExtension' => $fileExtension,
                'AllowedExtensions' => array_keys(ALLOWED_EXTENSIONS_MAP)
            ]
        ];
    }

    // 4. فحص محتوى الملف الفعلي (MIME Type Inspection via Fileinfo)
    // عدم الاعتماد مطلقاً على ترويسة المتصفح ($fileData['type'])
    $finfoHandle = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfoHandle === false) {
        return [
            'success' => false,
            'message' => 'فشل في تهيئة فاحص المحتوى (Fileinfo) على الخادم.',
            'details' => ['Error' => 'Unable to open fileinfo']
        ];
    }

    $detectedMimeType = (string)finfo_file($finfoHandle, $tmpFilePath);
    finfo_close($finfoHandle);

    // التأكد من أن الـ MIME الفعلي يطابق نوع الامتداد المصرح به
    $validMimesForExtension = ALLOWED_EXTENSIONS_MAP[$fileExtension];
    if (!in_array($detectedMimeType, $validMimesForExtension, true)) {
        return [
            'success' => false,
            'message' => sprintf(
                'تنبيه أمني (MIME Spoofing): نوع المحتوى الفعلي للملف (%s) لا يطابق امتداده الظاهري (.%s)! تم إحباط محاولة الرفع.',
                htmlspecialchars($detectedMimeType),
                htmlspecialchars($fileExtension)
            ),
            'details' => [
                'Extension'    => $fileExtension,
                'DetectedMime' => $detectedMimeType,
                'ExpectedMime' => $validMimesForExtension
            ]
        ];
    }

    // 5. توليد اسم ملف عشوائي ومحمي تشفيرياً لمنع ثغرات Path Traversal وتضارب الأسماء
    // استخدام bin2hex(random_bytes(16)) لإنتاج اسم بطول 32 حرف سداسي عشري
    $randomToken    = bin2hex(random_bytes(16));
    $safeStoredName = $randomToken . '.' . $fileExtension;
    $destination    = UPLOAD_DIR . '/' . $safeStoredName;

    // 6. نقل الملف المرفوع إلى مجلد التخزين وضبط الصلاحيات
    if (!move_uploaded_file($tmpFilePath, $destination)) {
        return [
            'success' => false,
            'message' => 'تعذر حفظ الملف في مجلد التخزين النهائي.',
            'details' => ['Destination' => $destination]
        ];
    }

    // ضبط صلاحيات الملف المرفوع لمنع تنفيذه (القراءة والكتابة للمالك، والقراءة للآخرين فقط)
    chmod($destination, 0644);

    return [
        'success' => true,
        'message' => 'تم فحص الملف ورفعه بنجاح وتأمينه وفق معايير الدفاع في العمق.',
        'details' => [
            'OriginalFilename'  => $originalName,
            'StoredFilename'    => $safeStoredName,
            'FileSize'          => round($fileSize / 1024, 2) . ' KB',
            'ValidatedExtension'=> $fileExtension,
            'ValidatedMimeType' => $detectedMimeType,
            'RelativePath'      => 'uploads/' . $safeStoredName
        ]
    ];
}

// المعالجة عند إرسال النموذج عبر HTTP POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['uploaded_file'])) {
        $uploadResult   = handleSecureUpload($_FILES['uploaded_file']);
        $statusMessage  = $uploadResult['message'];
        $statusType     = $uploadResult['success'] ? 'success' : 'danger';
        $debugDetails   = $uploadResult['details'] ?? [];
    } else {
        $statusMessage  = 'لم يتم إرسال أي ملف عبر المتغير [uploaded_file].';
        $statusType     = 'danger';
    }
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نظام رفع الملفات الآمن والتحقق متعدد الطبقات | التكليف الثاني عشر</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent: #38bdf8;
            --accent-hover: #0ea5e9;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --success-bg: #064e3b;
            --success-border: #10b981;
            --danger-bg: #450a0a;
            --danger-border: #ef4444;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2.5rem 1rem;
        }

        .container {
            width: 100%;
            max-width: 650px;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .badge {
            display: inline-block;
            background: rgba(56, 189, 248, 0.15);
            color: var(--accent);
            border: 1px solid rgba(56, 189, 248, 0.3);
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }

        h1 {
            font-size: 1.55rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            color: var(--text-main);
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 0.95rem;
            line-height: 1.5;
        }

        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.75rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
            margin-bottom: 1.5rem;
        }

        .rules-list {
            list-style: none;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.6rem;
            margin-bottom: 1.5rem;
            background: rgba(15, 23, 42, 0.6);
            padding: 0.85rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
        }

        .rules-list li {
            display: flex;
            align-items: center;
            gap: 0.4rem;
            color: var(--text-muted);
        }

        .rules-list li strong {
            color: var(--accent);
        }

        .dropzone {
            border: 2px dashed var(--border-color);
            border-radius: 8px;
            padding: 2rem 1rem;
            text-align: center;
            background: rgba(15, 23, 42, 0.4);
            transition: all 0.2s ease;
            cursor: pointer;
            margin-bottom: 1.25rem;
        }

        .dropzone:hover {
            border-color: var(--accent);
            background: rgba(56, 189, 248, 0.05);
        }

        .dropzone input[type="file"] {
            display: none;
        }

        .dropzone-label {
            cursor: pointer;
            display: block;
        }

        .file-icon {
            font-size: 2.2rem;
            margin-bottom: 0.5rem;
            display: block;
        }

        .filename-display {
            margin-top: 0.75rem;
            font-size: 0.9rem;
            color: var(--accent);
            font-weight: 500;
            word-break: break-all;
        }

        .btn-submit {
            width: 100%;
            background-color: var(--accent);
            color: #0f172a;
            border: none;
            padding: 0.85rem;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: background 0.2s;
        }

        .btn-submit:hover {
            background-color: var(--accent-hover);
        }

        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.25rem;
            border: 1px solid;
            font-size: 0.95rem;
            line-height: 1.5;
        }

        .alert-success {
            background-color: var(--success-bg);
            border-color: var(--success-border);
            color: #d1fae5;
        }

        .alert-danger {
            background-color: var(--danger-bg);
            border-color: var(--danger-border);
            color: #fee2e2;
        }

        .details-box {
            background: #0f172a;
            border-radius: 6px;
            padding: 0.85rem;
            margin-top: 0.75rem;
            font-size: 0.85rem;
            border: 1px solid var(--border-color);
        }

        .details-box table {
            width: 100%;
            border-collapse: collapse;
        }

        .details-box td {
            padding: 0.35rem 0.5rem;
            border-bottom: 1px solid #1e293b;
        }

        .details-box td:first-child {
            color: var(--text-muted);
            width: 38%;
            font-weight: 600;
        }

        .details-box td:last-child {
            color: #e2e8f0;
            font-family: monospace;
            direction: ltr;
            text-align: left;
        }

        .footer {
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <span class="badge">الأمن السيبراني | ورشة التطبيق العملي</span>
            <h1>نظام رفع الملفات الآمن والتحقق متعدد الطبقات</h1>
            <p class="subtitle">التكليف الثاني عشر: تطبيق استراتيجية الدفاع في العمق لمنع رفع Web Shells والتلاعب بالامتدادات</p>
        </header>

        <main class="card">
            <!-- عرض ملخص طبقات الحماية المتضمنة -->
            <ul class="rules-list">
                <li>🛡️ <strong>فحص الحجم:</strong> 2 ميجابايت كحد أقصى</li>
                <li>📋 <strong>الامتدادات:</strong> jpg, png, pdf</li>
                <li>🔍 <strong>الفحص الفعلي:</strong> Fileinfo (finfo_file)</li>
                <li>🔐 <strong>التسمية:</strong> bin2hex(random_bytes(16))</li>
            </ul>

            <!-- عرض تنبيه نتيجة الفحص والمعالجة -->
            <?php if ($statusMessage !== null): ?>
                <div class="alert alert-<?= $statusType ?>">
                    <strong><?= $statusType === 'success' ? '✔ نجاح التحقق:' : '✖ فشل التحقق الأمني:' ?></strong>
                    <?= htmlspecialchars($statusMessage) ?>

                    <?php if (!empty($debugDetails)): ?>
                        <div class="details-box">
                            <table>
                                <?php foreach ($debugDetails as $key => $val): ?>
                                    <tr>
                                        <td><?= htmlspecialchars((string)$key) ?>:</td>
                                        <td>
                                            <?php 
                                            if (is_array($val)) {
                                                echo htmlspecialchars(json_encode($val, JSON_UNESCAPED_SLASHES));
                                            } else {
                                                echo htmlspecialchars((string)$val);
                                            }
                                            ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>

            <!-- نموذج رفع الملف المخصص -->
            <form action="" method="POST" enctype="multipart/form-data">
                <div class="dropzone" onclick="document.getElementById('file-input').click();">
                    <span class="file-icon">📁</span>
                    <label class="dropzone-label">
                        <strong>اضغط لاختيار ملف</strong> أو قم بسحبه وإفلاته هنا
                        <input type="file" id="file-input" name="uploaded_file" required onchange="updateFileName(this)">
                    </label>
                    <div id="filename-display" class="filename-display">لم يتم تحديد أي ملف بعد</div>
                </div>

                <button type="submit" class="btn-submit">فحص ورفع الملف بالتحقق متعدد الطبقات</button>
            </form>
        </main>

        <footer class="footer">
            Cyber Bootcamp &copy; نظام رفع الملفات الآمن (Defense-in-Depth File Upload System)
        </footer>
    </div>

    <script>
        function updateFileName(input) {
            const display = document.getElementById('filename-display');
            if (input.files && input.files[0]) {
                const file = input.files[0];
                const sizeKb = (file.size / 1024).toFixed(2);
                display.innerText = `الملف المحدد: ${file.name} (${sizeKb} KB)`;
            } else {
                display.innerText = 'لم يتم تحديد أي ملف بعد';
            }
        }
    </script>
</body>
</html>

