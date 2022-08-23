​
# Android Sqlite 数据库升级

将每个版本的升级语句按版本顺序放在一个LIST中，这样在数据库版本升级的时候就不用做版本号判断了。List中的INDEX就是每个版本的SQL语句。这里只是做了一个简单的DEMO，没有考虑数据迁移。

如果是第一次安装，会调用onCreate，在onCreate里直接调用execUpgradSql(db, 0, 3)执行所有的SQL语句。

如果是从其它版本升级来的，比如从V2升到V3,则会调用onUpgrade,oldVersion是2，newVersion是3，这里调用execUpgradeSql(db, 2, 3),它只会执行V3新增的SQL语句。V1升到V3也是如此，它执行的是V2,V3的SQL。

以后每升级数据库，只要把这个版本对应的新增SQL放在LIST中就可以了。

```java
package com.gouhao.databaseupdate;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by GouHao on 2017/9/16.
 */

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = DatabaseHelper.class.getSimpleName();
    public static final String DB_NAME = "test.db";
    public static final String TABLE_USER_OLD = "user";
    public static final String TABLE_USER = "table_user";
    public static final String TABLE_STUDENT = "table_student";
    public static final int VERSION_CODE = 3;

    private List<List<String>> upgradeSqlList;

    public DatabaseHelper(Context context) {
        super(context, DB_NAME, null, VERSION_CODE);
        upgradeSqlList = new ArrayList<>();
        addUpgradeSqlVersion1();
        addUpgradeSqlVersion2();
        addUpgradeSqlVersion3();
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.d(TAG, "onCreate");
        execUpgradeSql(db, 0, VERSION_CODE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.d(TAG, "onUpgrade: oldVersion=" + oldVersion + ", newVersion=" + newVersion);
        execUpgradeSql(db, oldVersion, newVersion);
    }

    private void addUpgradeSqlVersion1() {
        List<String> sqlListVersion1 = new ArrayList<>();
        String userSql = "CREATE TABLE IF NOT EXISTS " + TABLE_USER_OLD + "(id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR);";
        sqlListVersion1.add(userSql);
        upgradeSqlList.add(sqlListVersion1);
    }

    private void addUpgradeSqlVersion2() {
        List<String> sqlListVersion2 = new ArrayList<>();
        String userAlter = "ALTER TABLE " + TABLE_USER_OLD + " ADD COLUMN age INTEGER;";
        sqlListVersion2.add(userAlter);
        upgradeSqlList.add(sqlListVersion2);
    }

    private void addUpgradeSqlVersion3() {
        List<String> sqlListVersion3 = new ArrayList<>();
        String alterUserTableName = "ALTER TABLE user RENAME TO " + TABLE_USER + ";";
        String tableStudent = "CREATE TABLE IF NOT EXISTS " + TABLE_STUDENT + "(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR);";
        sqlListVersion3.add(alterUserTableName);
        sqlListVersion3.add(tableStudent);
        upgradeSqlList.add(sqlListVersion3);
    }

    private void execUpgradeSql(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.d(TAG, "execUpgradeSql: oldVersion=" + oldVersion + ", newVersion=" + newVersion);
        for (int i = oldVersion; i < newVersion; i++) {
            List<String> sqlListVersion = upgradeSqlList.get(i);
            int size = sqlListVersion.size();
            for (int j = 0; j < size; j++) {
                try {
                    db.execSQL(sqlListVersion.get(j));
                    Log.d(TAG, "execUpgradeSql: version" + (i + 1) + " exec success:" + sqlListVersion.get(j));
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, "execUpgradeSql: version" + (i + 1) + " exec failed: " + sqlListVersion.get(j));
                }
            }
            Log.d(TAG, "execUpgradeSql: version" + (i + 1) + " exec success");
        }
    }

    @Override
    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.d(TAG, "onDowngrade: oldVersion: " + oldVersion + ", newVersion=" + newVersion);
    }
}
```


​