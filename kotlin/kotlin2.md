# **Kotlin的类型系统** 

### **基本数据类型和其他基本类型**

Java把基本类型和引用类型区分开，基本类型存值，引用类型存地址，还提供了基本类型的包装类型，比如：Integer等。Kotlin并不区分基本类型和引用类型，用的全是一个类型。

```kotlin
val i: Int = 1
val list: List<Int> = listOf(l, 2, 3)
```
上面的 i 在最后会编译成Java的int, 对于list中的数字编译成Integer。Kotlin会尽量使用基本类型，但是像集合类会用包装类型。

Kotlin与Java类型对照关系
* Int -> Byte, Short, Int, Long
* Float -> Float, Double
* Char -> Char
* Boolean -> Boolean

### **可空的基本数据类型**

所有类型都可在后面加 ? 表示该类型的可空版本，对于可空类型，Kotlin都会编译成包装类型，因为可空版本会有 null 值
```kotlin
/* Kotlin */
fun test(v : Int?) : Int? = null

/*java*/
public Integer test(Integer v){
    return null;
}
```

### **数字转换**
在Java中,会把数字转换成范围更大的类型，比如：int->long, float->double。但在Kotlin中不会自动转换，需要显式转换
```kotlin
fun main(args : Array<String>) {
    val i : Int = 1
//    val l : Long = i //编译错误
    
    val l : Long = i.toLong()
}
```

特殊情况，当写字面值的时候不需要显式的转换
```kotlin
fun test(l : Long) = println(l)

fun main(args : Array<String>) {
    test(33)

    val b : Byte = 1
    val l : Long = b + 3L

    //val l2 : Long = b + 3  //编译错误，b+3是Int
    val l2 : Long = b.toLong() + 3
}
```
注意上面的 l, l2, 如果直接用 b+3, 则会被认为是Int，需要先把b转成Long类型然后再加3, 3是字面值，所以会自动转换

**特殊类型**

Any, Any? 类型

和Java中的Object类差不多，Any 是Kotlin中所有非空类型的父类，包括基本类型，Any? 是所有可空类型的父类。Kotiin 函数使用 Any 时，它会被编译成 Java中Object。Any 有toString, equals, hashCode方法，但是它不能调用java.lang.Object的wait, notify等方法，可以手动转成 Object 去调用

```kotlin
val a : Any = "a"
(a as java.lang.Object).wait()
```

Unit 类型

Unit类型对应Java中的Void，作为函数返回值时可以省略，也不用写return，会被隐式的返回，不像Java中的Void，需要写一条return

Nothing 类型

Nothing类型的函数永远不会返回。比如许多测试库中的fail函数，还有无限循环的函数等

Noting类型没有任何值，仅做为函数返回值时有意义。

Nothing类型可以作为Elvis运算符的右边的表达式

```kotlin
fun fail(message: String): Nothing {
    throw IllegalStateException(message)
}

fun main(args : Array<String>) {
    val a : String? = "lala"
    val address = a ?: fail("No address")
    println(address)
}
```

### **集合与数组**

**只读集合与可变集合**

Kotlin将访问集合，和修改集合的接口分开，这是与Java最大的不同。每个Java的集合在Kotlin中都有两个版本。

只读集合继承自：kotlin.collections.Collection，这个接口除了访问集合，没有添加，删除的操作

可变集合继承自：kotlin.collections.MutableCollection,它又继承自kotlin.collections.Collection，MutableCollection有添加，移除，清空的能力

一般在任何地方都应该优先使用只读集合，只有在确定这个集合需要改变的时候使用可变集合。

在Kotlin中声明集合的方法：
|集合|只读|可变|
|:---:|:---:|:---|
|List|listOf|mutableListOf, arrayListOf|
|Set|setOf|mutableSetOf, hashSetOf, linkedSetOf, sortedSetOf|
|Map|mapOf|mutableMapOf, hashMapOf, linkedMapOf, sortedMapOf|


只读集合不一定是不可变的，一个集合可以被多个变量引用，你声明的是只读集合，其它地方可能是可变集合

```kotlin
fun main(args : Array<String>) {
    val list = mutableListOf("test", "lala")
    val l : List<String> = list
    val l1 : MutableList<String> = list
}
```
上面的l, l1 都引用的list集合，但是l1可以修改集合。如果在多线程中出现这种情况，就会导致ConcurrentModificationException，所以只读集合并不是线程安全的

Kotlin的只读，可变集合对Java是没有影响的，与Java交互时，对于Java两种集合都是可以修改的，所以就需要自己负责使用正确的类型

关于Java中定义的集合类型，Kotlin也把它看作平台类型，和对待普通平台类似一样，因为无法获取到它的只读或者可变性，需要我们自己去负责写出正确的类型，有下面几点考虑：
* 集合是否可空
* 集合中的元素是否可空
* 你的方法会不会修改集合

**数组**

Kotlin的数组是一个带有类型参数的类，其元素被指定为相应的类型，创建数组有以下方法：
* arrayOf, 它包含的元素是指定为该函数的实参
* arrayOfNulls, 创建一个给定大小的数组，包含的是 null 元素
* Array, Array构造方法接收数组大小和一个lambda表达式，调用lambda表达式来创建每一个元素
```kotlin
fun main(args : Array<String>) {
    val a1 = arrayOf(1, 2, 3)
    val a2 = arrayOfNulls<String>(8)
    val a3 = Array<Int>(3){ index -> index * index}

    println("a1: ${a1.joinToString()}\na2: ${a2.joinToString()}\na3: ${a3.joinToString()}")
}
```

数组类型参数始终会变成对象类型，所以 Array<Int> 编译成Java就是Integer[]。

要生成基本类型的数组，要使用每个类对应的 TypeArray类，比如：IntArray, ByteArray, CharArray等等。创建一个基本类型的数组有如下方法：
* 使用该类型的构造函数生成一个固定size大小的数组，数组中的每个值都会用该类型的默认值初始化好
* 调用各类型的工厂方法，比如 IntArray.intArrayOf。接收变长参数的值，并创建存储这些值的数组
* 另一种构造方法是接收一个大小，和生成各元素的lambda，和Array类似

```kotlin
fun main(args : Array<String>) {
    val a1 = intArrayOf(1, 2, 3)
    val a2 = IntArray(8)
    val a3 = IntArray(3){ index -> index * index}

    println("a1: ${a1.joinToString()}\na2: ${a2.joinToString()}\na3: ${a3.joinToString()}")
}
```
可以把装箱类型的数组调用 toIntArray 等相应的方法转成基本类型数组。