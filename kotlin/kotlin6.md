# **运算符重载及其他约定**
这个和C++的运算符重载类似，允许你为类定义一些运算符支持的操作，比如+，-，*，/等等，最终还是编译成函数去调用。

## **重载算术运算符**
```kotlin
data class Point(val x : Int, val y : Int){
    operator fun plus(other : Point) : Point{ //成员函数
        return Point(x + othe r.x, y + other.y)
    }
}

//operator fun Point.plus(other: Point) : Point{ //扩展函数
//    return Point(x + other.x, y + other.y)
//}

fun main(args : Array<String>) {
    val p1 = Point(2, 3)
    val p2 = Point(3, 4)
    println("p1+p2=${p1 + p2}")
}
```
上面定义了一个Point的加法运算符重载，使用的时候就可以直接使用+号进行运算。实际上编译之后还是调用函数：p1.plus(p2)。或者将其定义为扩展函数。

>从Java调用Kotlin的重载运算符直接调用函数

用关键字**operator**定义一个运算符重载函数，之后就可以用相应的符号进行操作，重载的运算符和普通运算符相同。

可重载的二元算术运算符

|表达式|函数名|
|---|---|
|a*b|times|
|a/b|div|
|a%b|mod|
|a+b|plus|
|a-b|minus|

上面的每个运算符都有一个复合赋值运算符，比如plusAssign, timesAssign等，复合运算符只是修改对象，所以如果定义了一个Unit类型的复合赋值运算符函数，当在使用+=，*=这些运算的时候，就会自动调用这些方法。


定义运算符时不要求两个运算数是相同类型，比如用一个数字来缩放一个点
```kotlin
operator fun Point.times(scale : Double) : Point{
    return Point((x * scale).toInt(), (y * scale).toInt())
}

operator fun Double.times(p : Point) : Point{
    return Point((this * p.x).toInt(), (this * p.y).toInt())
}

fun main(args : Array<String>) {
    val p1 = Point(2, 3)
    val p2 = Point(3, 4)
    println("p1+p2=${p1 + p2}")
    println("scale p1=${p1 * 1.5}")
    println("scale p1=${1.5 * p1}")
}
```
运算符重载是不支持交换性的，如果想要支持交换性必须为交换的类型定义一个重载运算符的扩展函数。像上面的Double.times。

Kotlin没有类似Java的位运算符，Kotlin的位运算符是中缀调用：

|位运算符|含义|
|---|---|
|shl|带符号左移|
|shr|带符号右移|
|ushr|无符号右移|
|and|与|
|or|或|
|xor|异或|
|inv|取反|

可重载的一元运算符：
|表达式|函数名|
|---|---|
|+a|unaryPlus|
|-a|unaryMinus|
|!a|not|
|a++,++a|inc|
|a--,--a|dec|

---
## **重载比较运算符**
比较运算符包含==, !=, >, >=, <, <=, ===。===不仅比较值还比较引用是否相同，===是不允许重载的。

Kotlin中按约定，对于==, !=的比较，调用的是equals方法，只以想重载这两个运算符，只需重载equals方法就可以。

对于大于，小于，只要实现Comparable<Type>接口就可以使用运算符去比较。

---
## **集合与区间的约定**
集合的可以使用下标对元素访问或者修改;可以使用in来检查是否在区间或者集合内。

Kotlin的集合可以使用map[key]来访问, 也可以用map[key]=Value来设值，这些是通过重载get, set运算符来实现。

```kotlin
operator fun Point.get(index : Int) : Int =
        when(index){
            0 -> x
            1 -> y
            else ->
                throw IndexOutOfBoundsException("error index $index")
        }

operator fun Point.set(index: Int, value : Int):Unit =
        when(index){
            0-> x = value
            1-> y = value
            else ->
                throw IndexOutOfBoundsException("error index $index")
        }
fun main(args : Array<String>) {
    var p = Point(3, 4)
    println("p[0]=${p[0]}")
    println("p[1]=${p[1]}")
    p[0] = 8
    p[1] = 2
    println("p=$p")
}
```
get函数的值不仅限于1个，也可以使用多个值访问，看需求，调用的时候，就像p[a,b]。set函数的最后一个参数用来接收等号右边的值。
 
**in约定符**

in约定符用来判断一个对象是否属于另一个对象，比如属于一个集合。

```kotlin
data class Line(val p1 : Point, val p2 : Point){
    operator fun contains(p : Point) : Boolean{
        return p.x in p1.x until p2.x &&
                p.y in p1.y until p2.y
    }
}

fun main(args : Array<String>) {
    var p = Point(10, 4)
    val line = Line(Point(2, 3), Point(8, 9))
    println("p in line = ${p in line}")
}
```
上面的例子用来判断一个点是否属于一条线，重载或者扩展contains函数可以实现in约定

**rangeTo约定符**
rangeTo用来创建一个区间。实现了rangeTo运算符函数，可以使用 .. 创建。

```kotlin
operator fun Point.rangeTo(p : Point) : Array<Point> =
    Array(p.x - x){
        Point(x + it, y)
    }

fun main(args : Array<String>) {
    val pointRange = Point(1, 2) .. Point(10, 3)
    for(p in pointRange){
        println("pointRange=$p")
    }
}
```
上面是胡写的鸽子，主要是演示rangeTo的用法。

>**注意:** rangeTo的优先级低于算术运算符优先级。

**for循环中使用iterator**

在for循环中也可以使用in运算符，这和前面的判断的in运算符不同，for循环中的in会被转化成java中的iterator迭代器，所以在for循环中要使用in去迭代，需要实现iterator的运算符重载函数。

---
## **解构声明和组件函数**

解构声明用来展开一个复合值，并使用它来初始化多个单独变量。一个解构声明看起来就像一个普通的变量声明，只不过括号里有多个值。

```kotlin
class Point(var x : Int, var y : Int)
operator fun Point.component1() = x
operator fun Point.component2() = y

fun main(args : Array<String>) {
    val point = Point(3, 4)
    val (px, py) = point
    println("px=$px, py=$py")
}
```
上面的componet1, componet2就是用来支持解构声明的。解构功能再次用到了约定，对解构声明中的每个变量，将调用相应的解构函数。

对于数据类，编译器为每个主构造函数中的成员变量自动生成了解构函数。

>**注意:** 解构函数不能无限声明，Kotlin只允许最多5个解构函数

解构声明还可以用在for循环中，比如迭代map：
```kotlin
fun test(map : Map<String, String>){
    for((key, value) in map){
        println("key=$key, value=$value")
    }
}
```
---
## **重用属性的访问逻辑：委托属性**

委托是一种设计模式，操作的对象不用自己完成任务，而是将工作委托给另一个辅助类。
```kotlin
class Test{
    var p : Type by Delegate()
}
```
上面是委托属性的语法，p将它的操作，通过关键字by委托给Delegete的一个实例。编译器会创建一个隐藏的对象：
```kotlin
class Test{
    val delegate = Delegate()
    var p : Type
        get() = delegate.getValue(...)
        set(value : Type) = delegate.setValue(...)
}
```
按照约定，Delegate类必须有getValue和setValue方法：
```kotlin
class Delegate{
    operator fun getValue(...){...}
    operator fun setValue(..., value : Type){...}
}
```
上面就是创建一个委托属性的模板，下面是几个委托属性在实际中使用的场景。

**惰性初始化**

在平时开发中，有些对象在第一次使用的时候才进行初始化。在Kotlin中可以使用lazy函数返回的委托，像下面这样：
```kotlin
class MainActivity{
    val alertDialog : AlertDialog by lazy {
        AlertDialog().apply{
            ...
        }
    }
}
```
lazy函数默认是线程安全的，可以指定使用的锁和不使用线程安全。