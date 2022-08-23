# **类，对象，接口**

## **定义类的继承结构**

**接口**  

接口和Java一样用 interface 定义，Kotlin接口中的方法可以有默认实现

```kotlin
interface ITest{
    fun test1()
    
    fun test2() = println("I am ITest test2")
}

class TestImpl : ITest{
    override fun test1() = println("I am TestImpl test1")
}
```
Kotlin中用冒号代替Java中的extends, implements，这个和C++的继承很像。只能继承一个类，实现多个接口，多个接口用逗号隔开。在重写父类的方法的时候，强制要用 override 修饰方法，防止意外重写，在Java中只要方法签名一样就算是重写。

如果一个类实现的两个接口有同名的默认实现方法，则子类必须要重写此方法，因为不知道该调用哪个。
```kotlin
interface ITest2{
    fun testFun()

    fun test2() = println("I am ITest2 test2")
}

class TestImpl : ITest, ITest2{
    override fun testFun() = println("I am TestImpl testFun")

    override fun test2() {
        super<ITest>.test2()
        super<ITest2>.test2()
    }

    override fun test1() = println("I am TestImpl test1")
}
```
可以用super<>指定调用哪个类的方法，在Java中是用ITest.super.test2()

> Kotlin 1.0 是以Java6为目标设计的，其并不支持接口中的 默认方法，它会把每个带默认方法的接口编译成一个普通接口和一个将方法体作为静态函
数的类的结合体。

**open, final, abstract修饰符**

在Java里类和方法默认都是可以继承，重写的，除非显式用final修饰，但在Kotlin中正好相反，类和方法默认都是final的，除非显示的用 **open** 修饰

重写了基类或接口的成员，默认也是open的，除非显示的标为final

```kotlin
//这个类是可以继承的
open class TestImpl : ITest, ITest2{
    //这个方法子类不可重写
    final override fun testFun() = println("I am TestImpl testFun") 

    //这个方法可以重写
    override fun test2() {
        super<ITest>.test2()
        super<ITest2>.test2()
    }

    //这个方法可以重写
    override fun test1() = println("I am TestImpl test1")
}
```

abstract 和Java中的一样，它的成员抽象方法默认是open的

类修饰符的意义：
|修饰符|相关成员|备注|
|:---:|---|---|
|final|不能被重写|类中成员默认使用|
|open|可以被重写|需要显式修饰|
|abstract|必须被重写|只能在抽象类中使用，抽象方法不能有实现|
|override|重写父类或接口中的成员|如果没有使用final修饰，重写的方法还是open|

**可见性修饰符**

Kotlin和Java类似，也有public, protected, private修饰符，但如果什么都不写，默认的不一样，Java默认是包内访问，Kotlin是public。Kotlin没有包内访问，它提供了一种新的修饰符 **internal**，模块内部可见。模块可以是一个Module, 一个maven或gradle项目等。

Kotlin只是将包作为一种组织代码的方式，并没有对可见性有作用。Java的包内访问也有缺点，如果在外部定义一个相同的包结构，就会得到包内访问的属性或方法。

另一个区别就是Kotlin允许在顶层声明中使用 private 修饰，包括类，函数，属性。这表示这些声明只能在声明它的文件里可见，这也是隐藏的另一种实现。

Kotlin中的修饰符：

|修饰符|类成员|顶层声明|
|---|---|---|
|public（默认）|所有地方可见|所有地方可见|
|internal|模块中可见|模块中可见|
|protected|子类中可见|-|
|private|类中可见|文件中可见|

```kotlin
internal open class TestImpl2 : ITest{
    override fun test1() = println("I am TestImpl2 test1")
    
    private fun test3() = println("I am TestImpl2 test3")
    
    protected fun test4() = println("I am TestImpl2 test4")
}

fun TestImpl2.funEx() { //错误，public方法暴露了internal类
    println("I am TestImpl2 ex")
    
    test3() //错误，扩展函数不能调用私有方法
    
    test4() //错误，扩展函数不能调用protected方法
}
```
Kotlin禁止从高可见类型去引用低可见类型，这会暴露低类型。一个通用的规则是：类的基础类型和类型参数列表中用到的所有类，或者函数的签名都有与这个类或者函数本身相同的可见性。这个规则可以确保你在需要调用函数或者继承一个类时能够始终访问到所有的类型。要解决上面例子中的问题，既可以把函数改为 internal 的，也可以把类改成 public。

Kotlin中的 protected 和Java中的不一样。Java中可以在同一个包类访问protected成员，Kotlin不允许这样做，只在它的子类可见。扩展函数也不能访问 private 和 protected 成员。

> 注意，Kotlin中的 private 类会编译成Java中的包内可见。internal会被编译成 public。

**内部类和嵌套类**
在Java的类中声明一个类，默认是内部类，要想变成嵌套类要加 static 修饰，而Kotlin默认是嵌套类，要想变成内部类要加 inner 修饰符。

|在类A中声明类B|Java|Kotlin|
|---|---|---|
|嵌套类(不存储外部类引用)|static class A|class A|
|内部类(存储外部类引用)|class A|inner class A|

Kotlin访问外部类的语法也不一样，需要使用 this@Outer去访问。在Java中是Outer.this
```kotlin
class Outer {
    inner class Inner {
        fun getOuterReference() : Outer = this@Outer
    }
}
```

**密封类**

```kotlin
open class ITest
class TestImpl1 : ITest()
class TestImpl2 : ITest()
fun testFun(cls : ITest) =
        when(cls){
            is TestImpl1 -> println("TestImpl1")
            is TestImpl2 -> println("TestImpl2")
            else -> println("Unknown")
        }

```
像上面这个例子，去判断类型时，总是要写一个else分支，如果你新加了一个子类，忘了在 when 中写分支就会走到 else。Kotlin为这种情况提供了一种解决方案：密封类。密封类用sealed修饰。对子类做出了严格限制，所有的子类必须定义在同一个文件中。

```kotlin
sealed class ITest
class TestImpl1 : ITest()
class TestImpl2 : ITest()
class TestImpl3 : ITest()

fun testFun(cls : ITest) =
        when(cls){
            is TestImpl1 -> println("TestImpl1")
            is TestImpl2 -> println("TestImpl2")
            is TestImpl3 -> println("TestImpl3")
        }
```

如果新增加一个子类而没有在 when 写分支的话，编译报错。sealed 隐含这个类是 open, 所以不需要再加 open。

不能声明一个 sealed 接口，因为这样的话Kotlin不能保证任何人都不能在Java中实现这个接口。

> 注意：Kotlin 1.0 对密封类限制很严格，必须将子类定义成嵌套类。

---
## **构造函数和属性**

Java中可以定义多个构造函数，Kotlin也一样，只不过做了一些修改，区分主构造函数和从构造函数，并且还有初始化语句块做一些初始化操作。

**构造方法和初始化语句块**
```kotlin
class User1 public constructor(name : String) //带一个参数的主构造方法
{
    val name : String //声明属性

    init {  //初始化语句块
        this.name = name
    }
}

class User2 constructor(nameArg : String){
    val name = nameArg //初始化属性
}

class User3(var name : String)

```
上面声明了三个类是同一个类的不同写法, User3是最简化的版本。

一般类成员的声明都写在花括号内，这种写在括号中的语句块叫**主构造方法**。这有两个目的，表明构造方法的参数以及用这些参数初始化属性。

constructor 用来声明一个主构造方法或从构造方法，如果主构造方法没有注解或者可见性修饰符，可以省略 constructor。

init 用来声明一个初始化语句块，初始化语句块可以写多个，按照定义的顺序执行。**主构造方法总是先执行，然后再执行初始化语句块，最后执行从构造函数**。

如果属性用主构造方法的参数来初始化，可以把属性的val/var加到参数的前面，进行简化，最终写下来就是User3的版本

同时也可以像函数那样为构造方法中的参数写默认值，这样就像在Java中重载了多个构造函数一样。
```kotlin
class User3(var name : String, val age : Int = 1)
fun main(args : Array<String>) {
    val user1 = User3("user1", 3)
    val user2 = User3("user2")
}
```
要创建一个实例，直接调用构造方法，不需要 new 关键字。

继承一个类的时候，也要先调用其构造函数。
```kotlin
open class TextView(val text : String) {
    constructor(text : String, v : Int) : this(text){
        println("contructor")
    }
}

class EditText : TextView {
    constructor(t: String) : super(t)
}
```
TextView中有主构造函数，每个从构造函数必须先调用主构造函数，和Java中一样可以用 this 去调用其它构造函数。子类也要显式调用父类的主构造函数。

**属性的getter,setter**

Kotlin中，接口可以声明抽象属性。其实也是方法，只不过换了一种表示方式。
```kotlin
interface User{
    val nickName : String
}

class User1(override val nickName: String) : User //主构造方法属性

class User2(val email : String) : User{
    override val nickName : String
        get() = email.substring(3)  //自定义getter
}

class User3(val a : Int) : User{
    override val nickName = a.toString() //属性初始化
}
```
上面的User类有一个 nickName 的属性，所以实现它的类都要有一个取得 nickName 值的方式，并不限制是存在一个字段还是通过getter获取。上例中User1, User3都是将值在到字段中，而User2是直接通过getter方法获取值，所以并没有字段去保存值。User2中的nickName每次获取都要进行一次计算，User3中的只是在初始化的时候执行一次。

接口中也可以包含有getter, setter的属性
```kotlin
interface User{
    val email : String
    val nickName : String
        get() = email.substringBefore('@')
}
```
email属性是必须要实现的，而nickName属性可以被子类继承。在接口的getter中不能访问支持字段。

支持字段和非支持字段其实就是在类中是否有保存值的字段。如果是使用默认的访问器，则会生成字段;如果自定义getter/setter，如果引用了 **field** 则会生成字段，否则不会生成。就像User2中的nickName一样。

```kotlin
open class User{
    var address = "unknown"
        protected set(value) {
            println("old=$field, new=$value")
            field = value
        }
}
```
上例中的User中在set中使用的field，所以会生成address字段保存值。在使用的时候直接用user.address = "address",这样相当于调用setter。还可以在getter/setter前加可见性修饰符来限制访问。

---
## **数据类和类委托**

数据类通常用来保存数据，没有其它的业务。Kotlin为这种类提供了简单的解决方案。在类前面加上 **data** 修饰符
```kotlin
data class User(val name: String, val age : Int)
```
这个类有name, age两个属性，并且Kotlin还会为data类自动生成，toString, equals, hashCode这些方法，equals和hashCode，是以主构造函数中的属性进行比较和生成的。

```kotlin
fun copy(name: String = this.name, age: Int = this.age) = User(name, age)
```
Kotlin为每个数据类生成了copy方法，可以用一个实例生成一个新实例，就像Java中的clone方法一样，实现一种原型模式。

类委托使用 **by** 关键字，可以将一个接口的实现委托给另一个类，比如装饰模式，代理模式等。
```kotlin
class ListImpl(override val size: Int) : Collection<String>{
    private val innerList = arrayListOf<String>()
    override fun containsAll(elements: Collection<String>): Boolean = innerList.containsAll(elements)

    override fun isEmpty(): Boolean = innerList.isEmpty()

    override fun iterator(): Iterator<String> = innerList.iterator()

    override fun contains(element: String): Boolean = innerList.contains(element)
}

class ListImpl2(private val innerList : List<String>) : Collection<String> by innerList
```
在类中只写想重写的方法。

---
## **object 关键字**

object 关键字被用来声明一个类并创建一个类的实例。用法有下面几种情况：
* 用对象声明来定义单例
* 伴生对象可以持有工厂方法和其他与这个类相关，但在调用时并不依赖实例，它们的成员可以通过类名来访问
* 对象表达式用来替代Java匿名类

**对象声明**

在Java中定义单例一般都是通过将构造方法声明为private，然后定义一个静态字段持有该类的实例。在Kotlin中为单例模式提供了语言级别的支持。
```kotlin
object ActivityManager{
    val activityList : MutableList<String> = mutableListOf()

    fun getActivity(index : Int) : String = activityList[index]
}

fun main(args : Array<String>) {
    ActivityManager.activityList[0] = "hello"
    ActivityManager.getActivity(0)
}
```
与类一个，一个对象声明也可以包含属性，方法，初始化语句块的声明，但是**不允许有构造方法**，对象声明在声明的时候就创建了对象，所以声明构造方法是没有意义的，对象声明也可以继承类和接口。

在类中定义一个嵌套类的对象声明，同样也是单例。

> 在Java中使用Kotlin的对象声明，用这种ActivityManager.INSTANCE.调用，因为每个Kotlin的对象声明中都有一个INSTANCE静态实例。

**伴生对象**

Kotlin中没有Java的static关键字，作为替代Kotlin有顶层函数和对象声明，大多数情况下推荐使用顶层函数，也可以使用伴生对象来实现相似的能力。
```kotlin
class ActivityManager private constructor(age : Int){
    companion object {
        fun testFun() = println("testFun")
    }
}

fun main(args : Array<String>) {
   ActivityManager.testFun() 
}
```
使用关键字 **companion** 修饰 object,可产生一个伴生对象。

伴生对象可以调用private的构造方法，这可以用来实现工厂方法模式。
```kotlin
class User private constructor(val name : String){
    companion object {
        fun createUser1() = User("User1")
        
        fun createUser2() = User("User2")
    }
}

fun main(args : Array<String>) {
    User.createUser1()
    User.createUser2()
}
```
伴生对象编译成Java后，会生成一个嵌套类，和一个静态的该嵌套类字段，直接使用容器类名调用方法，实际上是调用嵌套类的静态方法。

伴生对象可以有名字，扩展方法。如果伴生对象没有名字，则默认为Companion,如果有名字则是实际名字

```kotlin
fun User.Companion.sayHello() = println("Hello") //扩展伴生对象
```

**对象表达式**

object 关键字不仅可以用来声明对象，还可以声明匿名对象，就像Java中的匿名内部类一样。

```kotlin
button.setOnClickListener(
    object : OnClickListener(){
        override fun onCLick(v : View){
        }
    }
)
```
除了没有对象名字，其他都和对象声明是一样的，对象表达式声明了一个对象并对象了一个实例。对象表达式可以实现多个接口

>  与对象声明不同，匿名对象不是单例的，每次都会创建新对象。

与Java匿名类一样，可以在匿名类中访问方法中的变量。但Java中只能访问final变量，Kotlin中没有限制，还可以改变外部变量的值