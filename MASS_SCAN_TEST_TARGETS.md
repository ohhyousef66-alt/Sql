# قائمة مواقع الاختبار - Mass Scanner Test

## المواقع العشرة للاختبار:

1. http://testphp.vulnweb.com/artists.php?artist=1
2. http://testphp.vulnweb.com/listproducts.php?cat=1
3. http://testphp.vulnweb.com/showimage.php?file=1
4. http://testphp.vulnweb.com/comment.php?id=1
5. http://testphp.vulnweb.com/product.php?pic=1
6. http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12
7. http://testphp.vulnweb.com/artists.php?artist=2
8. http://testphp.vulnweb.com/listproducts.php?cat=2
9. http://testphp.vulnweb.com/artists.php?artist=3
10. http://testphp.vulnweb.com/listproducts.php?cat=3

## نسخة نصية (للنسخ المباشر):
```
http://testphp.vulnweb.com/artists.php?artist=1
http://testphp.vulnweb.com/listproducts.php?cat=1
http://testphp.vulnweb.com/showimage.php?file=1
http://testphp.vulnweb.com/comment.php?id=1
http://testphp.vulnweb.com/product.php?pic=1
http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12
http://testphp.vulnweb.com/artists.php?artist=2
http://testphp.vulnweb.com/listproducts.php?cat=2
http://testphp.vulnweb.com/artists.php?artist=3
http://testphp.vulnweb.com/listproducts.php?cat=3
```

## الملاحظات:
- جميع المواقع من testphp.vulnweb.com (موقع اختبار قانوني)
- مواقع مختلفة بمعاملات مختلفة
- بعضها vulnerable وبعضها قد لا يكون

## المتوقع:
- اكتشاف الثغرات في المواقع الضعيفة
- Auto-verification للثغرات المكتشفة
- ظهور Success Box للثغرات المؤكدة
- إمكانية الانتقال لصفحة Dump
