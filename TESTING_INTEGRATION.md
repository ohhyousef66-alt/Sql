# 🚀 دليل اختبار تكامل Pipeline

## ✅ التكامل مكتمل!

تم دمج نظام **Pipeline المهني** مع الـ Scanner الموجود بنجاح. الآن النظام يعمل بـ:
- ✅ Confirmation Gate (بوابة التأكيد)
- ✅ Database Fingerprinting (تحديد نوع قاعدة البيانات)
- ✅ Post-Confirmation Enumeration (استخراج البيانات)
- ✅ Real Results Storage (حفظ نتائج حقيقية)

## 🧪 اختبار سريع

### 1. تشغيل الـ Server
```bash
npm run dev
```

### 2. تشغيل سكريبت الاختبار
```bash
./test-integration.sh
```

هذا السكريبت سيقوم بـ:
1. إنشاء Single Scan على موقع تجريبي
2. انتظار اكتمال الـ Scan
3. عرض الـ Logs
4. عرض الثغرات المُكتشفة
5. عرض نتائج الـ Enumeration (databases, tables, columns)

### 3. اختبار يدوي

#### إنشاء Single Scan
```bash
curl -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://testphp.vulnweb.com/artists.php?artist=1",
    "scanMode": "sqli",
    "threads": 10
  }'
```

#### التحقق من الحالة
```bash
curl http://localhost:5000/api/scans/1
```

#### عرض الثغرات
```bash
curl http://localhost:5000/api/scans/1/vulnerabilities
```

#### عرض نتائج Enumeration
```bash
curl http://localhost:5000/api/scans/1/enumeration
```

#### عرض الـ Logs
```bash
curl http://localhost:5000/api/scans/1/logs
```

## 🎯 ما يجب أن تراه

### في الـ Logs
```
INFO: 🔬 Starting Post-Confirmation Pipeline
INFO: 📊 Added 5 signals to confirmation gate
INFO: ✅ Confirmation Gate: PASSED
INFO: 🔍 Database: mysql 5.7.34
INFO: 📚 Enumeration: Found 3 databases, 15 tables
```

### في الـ Enumeration Results
```json
[
  {
    "id": 1,
    "databaseName": "production_db",
    "dbType": "mysql",
    "tableCount": 5,
    "tables": [
      {
        "id": 1,
        "tableName": "users",
        "columnCount": 7,
        "columns": [
          {"columnName": "id"},
          {"columnName": "username"},
          {"columnName": "email"},
          {"columnName": "password_hash"}
        ]
      }
    ]
  }
]
```

## 🔍 Mass Scan Test

### إنشاء Batch Scan
```bash
curl -X POST http://localhost:5000/api/scans/batch \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrls": [
      "http://testphp.vulnweb.com/artists.php?artist=1",
      "http://testphp.vulnweb.com/listproducts.php?cat=1",
      "http://testphp.vulnweb.com/showimage.php?file=1"
    ],
    "threads": 10
  }'
```

Response:
```json
{
  "parentScanId": 1,
  "childScanIds": [2, 3, 4]
}
```

### التحقق من النتائج لكل موقع
```bash
# Parent scan
curl http://localhost:5000/api/scans/1

# Child scans
curl http://localhost:5000/api/scans/1/children

# Enumeration لكل موقع
curl http://localhost:5000/api/scans/2/enumeration
curl http://localhost:5000/api/scans/3/enumeration
curl http://localhost:5000/api/scans/4/enumeration
```

## 📊 التحقق من قاعدة البيانات

```sql
-- عرض جميع الـ databases المُستخرجة
SELECT * FROM extracted_databases;

-- عرض الـ tables المُستخرجة
SELECT ed.database_name, et.table_name, et.column_count
FROM extracted_databases ed
JOIN extracted_tables et ON et.database_id = ed.id
ORDER BY ed.id, et.id;

-- عرض الـ columns المُستخرجة
SELECT ed.database_name, et.table_name, ec.column_name
FROM extracted_databases ed
JOIN extracted_tables et ON et.database_id = ed.id
JOIN extracted_columns ec ON ec.table_id = et.id
ORDER BY ed.id, et.id, ec.id;
```

## 🐛 استكشاف الأخطاء

### المشكلة: لم تظهر نتائج Enumeration
**الأسباب المحتملة**:
1. **Confirmation Gate لم تُجتَز**: راجع الـ Logs للتأكد من رؤية "Confirmation Gate: PASSED"
2. **Database Fingerprinting فشل**: تأكد من أن نوع قاعدة البيانات مدعوم
3. **Enumeration معطل**: تأكد من `enumerationEnabled: true` في الكود

**الحل**:
```bash
# راجع الـ Logs
curl http://localhost:5000/api/scans/1/logs | jq '.[] | select(.message | contains("Pipeline"))'

# راجع الثغرات المُكتشفة
curl http://localhost:5000/api/scans/1/vulnerabilities | jq '.[0]'
```

### المشكلة: Confirmation Gate تُحجَب دائماً
**الأسباب المحتملة**:
1. **إشارة واحدة فقط**: يحتاج إلى 2+ إشارات مستقلة
2. **نفس التقنية**: يجب أن تكون التقنيات مختلفة
3. **ثقة منخفضة**: يحتاج confidence >= 75%

**الحل**:
انتظر اكتشاف المزيد من الثغرات أو قلل من متطلبات الـ Confirmation Gate في:
```typescript
// server/scanner/integrated-pipeline-adapter.ts
this.confirmationGate = new ConfirmationGate({
  minimumSignals: 1,  // كان 2
  minimumConfidence: ConfidenceLevel.MEDIUM,  // كان HIGH
  requireDifferentTechniques: false,  // كان true
});
```

### المشكلة: Scanner يتعطل
**الحل**:
```bash
# راجع Console للأخطاء
npm run dev

# راجع Traffic Logs
curl http://localhost:5000/api/scans/1/traffic | jq '.[] | select(.statusCode != 200)'
```

## 📚 الوثائق الكاملة

- **Pipeline Architecture**: `server/scanner/pipeline/README.md`
- **Engineering Docs**: `server/scanner/pipeline/ENGINEERING_DOCUMENTATION.md`
- **Integration Details**: `INTEGRATION_COMPLETED.md`
- **Pipeline Summary**: `PIPELINE_IMPLEMENTATION_SUMMARY.md`

## 🎯 Next Steps

1. ✅ اختبر Single Scan
2. ✅ اختبر Mass Scan
3. ✅ تأكد من ظهور Enumeration Results
4. ✅ راجع الـ Database (extracted_databases, extracted_tables, extracted_columns)
5. 🔄 اختبر على مواقع حقيقية (بتصريح!)

## ⚠️ تحذيرات مهمة

- **LEGAL USE ONLY**: استخدم فقط على مواقع لديك تصريح باختبارها
- **Enumeration OPT-IN**: معطل افتراضياً لأسباب قانونية وأخلاقية
- **Rate Limiting**: يتم تطبيقه تلقائياً لتجنب إرهاق الخوادم
- **Audit Trail**: كل عملية مسجلة للمراجعة

---

**Status**: ✅ Ready for Testing  
**Last Updated**: 2024  
**Version**: 1.0.0
