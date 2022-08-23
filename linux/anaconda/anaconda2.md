## 简介
本次介绍anaconda的运行流程及一些调试方法，源码基于anaconda-21.48.22.158。

## 运行流程
anaconda的主函数入口在anaconda这个文件里。开始主要是解析命令行参数，初始化日志等工作。

在949行创建了Anaconda对象，这个对象会控制整个安装过程，在后面见到的所有anaconda对象都是这个对象。Anaconda类在pyanaconda/anaconda.py。
```py
from pyanaconda.anaconda import Anaconda
anaconda = Anaconda()
```
接下来就是配置Anaconda这个对象，及创建ksdata。ksdata在自动安装的时候提供数据，本篇不涉及。

在1259行，调用了setupDisplay。setupDisplay完成了两件重要的事：运行Xorg程序和初始化Anaconda的_intf对象。
```py
main->setupDisplay

def setupDisplay(anaconda, options, addons=None):

    ......

    # check_memory may have changed the display mode
    want_x = want_x and (anaconda.displayMode == "g")
    if want_x:
        try:
            startX11(xtimeout)
            doStartupX11Actions()
        except (OSError, RuntimeError) as e:
            log.warning("X startup failed: %s", e)
            stdoutLog.warning("X startup failed, falling back to text mode")
            anaconda.displayMode = 't'
            graphical_failed = 1
            time.sleep(2)

        if not graphical_failed:
            doExtraX11Actions(options.runres)

    ......

    # with X running we can initialize the UI interface
    anaconda.initInterface(addons)

    anaconda.instClass.configure(anaconda)

    # report if starting the GUI failed
    anaconda.gui_startup_failed = bool(graphical_failed)
```
displayMode有三种模式：g,t,c。g表示图形界面；t和c表示命令行安装。want_x初始化在省略的代码里，如果以图形界面安装的话want_x是True。

在startX11启动Xorg程序，会启动界面，之后会做一些配置。如果启动Xorg失败，则将displayMode改为t以命令行模式安装。

anaconda.initInterface(addons)这一句会初始化_intf对象。
```py
main->setupDisplay->initInterface

def initInterface(self, addon_paths=None):
    if self._intf:
        raise RuntimeError("Second attempt to initialize the InstallInterface")

    if self.displayMode == 'g':
        from pyanaconda.ui.gui import GraphicalUserInterface
        # Run the GUI in non-fullscreen mode, so live installs can still
        # use the window manager
        self._intf = GraphicalUserInterface(self.storage, self.payload,
                                            self.instClass, gui_lock=self.gui_initialized,
                                            fullscreen=False)

        # needs to be refreshed now we know if gui or tui will take place
        addon_paths = addons.collect_addon_paths(constants.ADDON_PATHS,
                                                    ui_subdir="gui")
    elif self.displayMode in ['t', 'c']: # text and command line are the same
        from pyanaconda.ui.tui import TextUserInterface
        self._intf = TextUserInterface(self.storage, self.payload,
                                        self.instClass)

        # needs to be refreshed now we know if gui or tui will take place
        addon_paths = addons.collect_addon_paths(constants.ADDON_PATHS,
                                                    ui_subdir="tui")
    else:
        raise RuntimeError("Unsupported displayMode: %s" % self.displayMode)

    if addon_paths:
        self._intf.update_paths(addon_paths)
```
这个方法就是根据displayMode的值去初始化_intf这个字段。图形安装会把_intf初始化成GraphicalUserInterface对象。GraphicalUserInterface类在pyanaconda/ui/gui/__init__.py文件里。

然后去根据收集addon_paths，addon_paths是一些附加的扩展安装选项，它们的代码没有anaconda里，而是单独提供的。像安装的时候有个选项是选择是否开启KDump，这个就是在addon_paths里。

接下来会根据选项是进入救援模式还是安装模式：
```py
if flags.rescue_mode:
    from pyanaconda.ui.tui.simpleline import App
    from pyanaconda.rescue import RescueMode
    app = App("Rescue Mode")
    spoke = RescueMode(app, anaconda.ksdata, anaconda.storage)
    app.schedule_screen(spoke)
    app.run()
else:
    cleanPStore()

......

anaconda._intf.setup(ksdata)
anaconda._intf.run()
```
我们只看安装模式，首先会调用_intf的setup方法，setup方法主要就是收集需要展示的窗口和spoke,hub这些。spoke,hub等这些界面上的东西在上篇文章中有说过。然后调用_intf.run开始运行安装流程。anaconda._intf在上说过，它被初始化为GraphicalUserInterface。

_intf.setup方法直接调了self.getActionClasses方法：
```py
main->anaconda._intf.setup->getActionClasses

def __init__():
    ......
    basemask = "pyanaconda.ui"
    basepath = os.path.dirname(__file__)
    updatepath = "/tmp/updates/pyanaconda/ui"
    sitepackages = [os.path.join(dir, "pyanaconda", "ui")
                    for dir in site.getsitepackages()]
    pathlist = set([updatepath, basepath] + sitepackages)

    paths = UserInterface.paths + {
            "categories": [(basemask + ".categories.%s",
                        os.path.join(path, "categories"))
                        for path in pathlist],
            "spokes": [(basemask + ".gui.spokes.%s",
                        os.path.join(path, "gui/spokes"))
                        for path in pathlist],
            "hubs": [(basemask + ".gui.hubs.%s",
                      os.path.join(path, "gui/hubs"))
                      for path in pathlist]
            }
def setup(self, data):
    self._actions = self.getActionClasses(self._list_hubs())
    self.data = data

def getActionClasses(self, hubs):
    """Grab all relevant standalone spokes, add them to the passed
        list of hubs and order the list according to the
        relationships between hubs and standalones."""
    from pyanaconda.ui.gui.spokes import StandaloneSpoke

    # First, grab a list of all the standalone spokes.
    standalones = self._collectActionClasses(self.paths["spokes"], StandaloneSpoke)

    # Second, order them according to their relationship
    return self._orderActionClasses(standalones, hubs)
```
getActionClasses调用了_collectActionClasses去收集，self.paths是在GraphicalUserInterface初始化的是一个字典。它的每一项都是列表，列表里又包了个元组。每个元组的第一项是匹配模式，第二项是路径。

上面三个路径：basepath, updatepath, sitepackages。basepath就是当前文件夹，updatepath是写死的，sitepackages就是所有python的site-packages路径，比如:/usr/lib(lib64)/python2.7(python3.6)/site-packages。前面两个路径都是固定的，后面这个路径比较多。其实大多数情况下都在找的site-packages这个路径下的，也就是我们源码的pyanaconda中的。

_collectActionClasses的第二个参数是父类名，这里传的是StandaloneSpoke。

_collectActionClasses在父类UserInterface中：
```py
main->anaconda._intf.setup->getActionClasses->_collectActionClasses

def _collectActionClasses(self, module_pattern_w_path, standalone_class):
    standalones = []

    for module_pattern, path in module_pattern_w_path:
        standalones.extend(collect(module_pattern, path, lambda obj: issubclass(obj, standalone_class) and \
                                    getattr(obj, "preForHub", False) or getattr(obj, "postForHub", False)))

    return standalones
```
收集过程比较简单，主要调用collect去收集，collect是根据匹配模式筛选是StancaloneSpoke的子类，并且不能同时有preForHub, postForHub这两个字段。这里找出来的基本上都是pyanaconda/ui/gui/spokes里的类。

再回到getActionClasses里，第二步调用_orderActionClasses给上面找出的spoke排序，第二个参数传的是hubs, hubs是从setup传进来的self._list_hubs()。

```py
def _list_hubs(self):
    """Return a list of Hub classes to be imported to this interface"""
    from pyanaconda.ui.gui.hubs.summary import SummaryHub
    from pyanaconda.ui.gui.hubs.progress import ProgressHub
    return [SummaryHub, ProgressHub]
```
只有两个hub, SummaryHub和ProgressHub，关于这两个hub详细说明，请看上一篇文章。

```py
def _orderActionClasses(self, spokes, hubs):

    actionClasses = []
    for hub in hubs:
        actionClasses.extend(sorted(filter(lambda obj, h=hub: getattr(obj, "preForHub", None) == h, spokes),
                                    key=lambda obj: obj.priority))
        actionClasses.append(hub)
        actionClasses.extend(sorted(filter(lambda obj, h=hub: getattr(obj, "postForHub", None) == h, spokes),
                                    key=lambda obj: obj.priority))

    return actionClasses
```
_orderActionClasses主要将spoke按照hub进行分类，保存到一个列表中。

首先是找出在当前hub之前运行的spoke, 也就是preForHub等于当前hub的spoke，然后再根据priority排序。整个代码中只有两个spoke的这个字段有值，分别是NetworkStandaloneSpoke(network.py), WelcomeLanguageSpoke(welcom.py)。
```py
class WelcomeLanguageSpoke(LangLocaleHandler, StandaloneSpoke):
    mainWidgetName = "welcomeWindow"
    focusWidgetName = "languageEntry"
    uiFile = "spokes/welcome.glade"
    helpFile = "WelcomeSpoke.xml"
    builderObjects = ["languageStore", "languageStoreFilter", "localeStore",
                      "welcomeWindow", "betaWarnDialog", "unsupportedHardwareDialog"]

    preForHub = SummaryHub
    priority = 0

class NetworkStandaloneSpoke(StandaloneSpoke):
    builderObjects = ["networkStandaloneWindow", "networkControlBox_vbox", "liststore_wireless_network", "liststore_devices", "add_device_dialog", "liststore_add_device"]
    mainWidgetName = "networkStandaloneWindow"
    uiFile = "spokes/network.glade"

    preForHub = SummaryHub
    priority = 10    
```
然后将当前hub加入列表。再找出要在hub之后运行的spoke, 就是postForHub等于hub的spoke加入列表，目前代码里没有spoke的postForHub有值。

所以在setup完成之后，self._actions里的值应该是[WelcomeLanguageSpoke, NetworkStandaloneSpoke, SummaryHub, ProgressHub]。也就是我们平时安装的流程：选择语言界面->配置网络界面->选择软件，磁盘等那个界面->安装界面。

在anaconda._intf.setup完成之后就是anaconda._intf.run:
```py
def run(self):
    ......

    # Apply a widget-scale to hidpi monitors
    self._widgetScale()

    while not self._currentAction:
        self._currentAction = self._instantiateAction(self._actions[0])
        if not self._currentAction:
            self._actions.pop(0)

        if not self._actions:
            return

    self._currentAction.initialize()
    self._currentAction.entry()
    self._currentAction.refresh()

    self._currentAction.window.set_beta(not self._isFinal)
    self._currentAction.window.set_property("distribution", self._distributionText().upper())

    # Set some program-wide settings.
    settings = Gtk.Settings.get_default()
    settings.set_property("gtk-font-name", "Cantarell")
    settings.set_property("gtk-icon-theme-name", "gnome")

    # Apply the application stylesheet
    provider = Gtk.CssProvider()
    provider.load_from_path("/usr/share/anaconda/anaconda-gtk.css")
    Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    # Look for updates to the stylesheet and apply them at a higher priority
    for updates_dir in ("updates", "product"):
        updates_css = "/run/install/%s/anaconda-gtk.css" % updates_dir
        if os.path.exists(updates_css):
            provider = Gtk.CssProvider()
            provider.load_from_path(updates_css)
            Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), provider,
                    STYLE_PROVIDER_PRIORITY_UPDATES)

    # try to make sure a logo image is present
    self._assureLogoImage()

    self.mainWindow.setCurrentAction(self._currentAction)

    # Do this at the last possible minute.
    unbusyCursor()

    Gtk.main()
```
首先调用_instantiateAction创建一个action, _instantiateAction比较简单就是创建一个传入的类的实例然后给按钮设置一些回调函数。

```py
def _instantiateAction(self, actionClass):
    # Instantiate an action on-demand, passing the arguments defining our
    # spoke API and setting up continue/quit signal handlers.
    obj = actionClass(self.data, self.storage, self.payload, self.instclass)

    # set spoke search paths in Hubs
    if hasattr(obj, "set_path"):
        obj.set_path("spokes", self.paths["spokes"])
        obj.set_path("categories", self.paths["categories"])

    # If we are doing a kickstart install, some standalone spokes
    # could already be filled out.  In that case, we do not want
    # to display them.
    if self._is_standalone(obj) and obj.completed:
        del(obj)
        return None

    # Use connect_after so classes can add actions before we change screens
    obj.window.connect_after("continue-clicked", self._on_continue_clicked)
    obj.window.connect_after("help-button-clicked", self._on_help_clicked, obj)
    obj.window.connect_after("quit-clicked", self._on_quit_clicked)

    return obj
```
经过while循环后，self._currentAction从self._actions里取出一个spoke或hub运行。

然后调用self._currentAction的initialize， entry， refresh方法，然后设置debug标志，版本号和设置样式文件anaconda-gtk.css，设置logo图片等。

最后，调用self.mainWindow.setCurrentAction(self._currentAction)会将界面显示出来。

刚才在_instantiateAction里创建action时，给continue-clicked注册的回调是self._on_continue_clicked。
```py
def _on_continue_clicked(self, win, user_data=None):
    ......

    nextAction = None
    ndx = 0

    ......

    while not nextAction:
        nextAction = self._instantiateAction(self._actions[1])
        if not nextAction:
            self._actions.pop(1)

        if not self._actions:
            sys.exit(0)
            return

    nextAction.initialize()
    nextAction.window.set_beta(self._currentAction.window.get_beta())
    nextAction.window.set_property("distribution", self._distributionText().upper())

    if not nextAction.showable:
        self._currentAction.window.hide()
        self._actions.pop(0)
        self._on_continue_clicked(nextAction)
        return

    self._currentAction.exit()
    nextAction.entry()

    nextAction.refresh()

    # Do this last.  Setting up curAction could take a while, and we want
    # to leave something on the screen while we work.
    self.mainWindow.setCurrentAction(nextAction)
    self._currentAction = nextAction
    self._actions.pop(0)
```
这个函数在我们点击每个界面上的继续或者下一步的时候会回调。贴出的代码省略了其他几种情况，只是主流程。

_on_continue_clicked的流程和run方法差不多，只是它是找下一个action。在run方法中给_instantiateAction传的是self._actions[0], 这里传的是self._actions[1]。

找到下一个action后先初始化，再调用self._currentAction.exit()退出当前action。然后再调用nextAction的entry和refresh，并把self._actions(0)弹出。

这样，整个安装程序就运转起来了。

hub比较特殊应该它包含其它的spoke，界面的显示主要是在父类Hub中实现的，代码在pyanaconda/ui/gui/hubs/__init__.py。

```py
def refresh(self):
    GUIObject.refresh(self)
    self._createBox()   

    GLib.timeout_add(100, self._update_spokes)

def _createBox(self):
    ......

    cats_and_spokes = self._collectCategoriesAndSpokes()
    categories = cats_and_spokes.keys()

    grid = Gtk.Grid(row_spacing=6, column_spacing=6, column_homogeneous=True,
                    margin_bottom=12)

    row = 0

    for c in sorted(categories, key=lambda c: c.title):
        obj = c()

        selectors = []
        for spokeClass in sorted(cats_and_spokes[c], key=lambda s: s.title):
            ......

            spoke = spokeClass(self.data, self.storage, self.payload, self.instclass)
            spoke.window.set_beta(self.window.get_beta())
            spoke.window.set_property("distribution", distributionText().upper())

            ......

            spoke.selector = AnacondaWidgets.SpokeSelector(C_("GUI|Spoke", spoke.title),
                    spoke.icon)

            ......

            selectors.append(spoke.selector)

        if not selectors:
            continue

        label = Gtk.Label(label="<span font-desc=\"Sans 14\">%s</span>" % escape_markup(_(obj.title)),
                            use_markup=True, halign=Gtk.Align.START, margin_top=12, margin_bottom=12)
        grid.attach(label, 0, row, 2, 1)
        row += 1

        col = 0
        for selector in selectors:
            selector.set_margin_left(12)
            grid.attach(selector, col, row, 1, 1)
            col = int(not col)
            if col == 0:
                row += 1

        # If this category contains an odd number of selectors, the above
        # row += 1 will not have run for the last row, which puts the next
        # category's title in the wrong place.
        if len(selectors) % 2:
            row += 1

    # initialization of all expected spokes has been started, so notify the controller
    hub_controller = lifecycle.get_controller_by_name(self.__class__.__name__)
    if hub_controller:
        hub_controller.all_modules_added()
    else:
        log.error("Initialization controller for hub %s expected but missing.", self.__class__.__name__)

    spokeArea = self.window.get_spoke_area()
    viewport = Gtk.Viewport()
    viewport.add(grid)
    spokeArea.add(viewport)

    setViewportBackground(viewport)
    self._updateContinue()
```
在_refresh里调用_createBox。_createBox会根据根据类别收集相关的spoke，具体过程在_collectCategoriesAndSpokes这个函数里，收集完之后。类别相关类在pyanaconda/ui/categories里，具体的spoke和类别的对应关系在上一篇说过。

然后每个类别，创建相应的spoke类实例和SpokeSelector，SpokeSelector就是一个可点击的按钮。然后对这些按钮进行排版。

## 调试方法
下面是我用过的一些调试方法，分享给大家：

1.如果只是看界面效果，直接在命令行运行anaconda就可以，命令：
```sh
anaconda --dirinstall [文件夹路径] --repo [文件夹路径]
```
--dirinstall：给文件夹里安装。建个空文件夹，给里面装。这个主要是为了看安装进度条那个界面。但这个选项，选磁盘那个不显示。

--repo：指定一个yum的仓库。我是直接把镜像里的Packages拷到本地，直接指定就行了。没有这个选软件那个选项不显示。

如果是在命令行运行，不要点anaconda界面上的退出，那个退出按钮会重启机子，直接在命令行kill。

2.真机调试
在真机上调试，可以看真实的安装过程，就是比较麻烦要拷代码。在真实装机的时候，ctrl+alt+f6是安装程序界面，ctrl+alt+f1~f5是命令行终端，在ctrl+alt+f1这个终端上可以按TAB切换日志，下面有提示。
```
1. rpmbuild -bi ~/rpmbuild/SPEC/anaconda.spec
2. 把~/rpmbuild/BUILDROOT/anaconda-21.48.22.158-1.el7.x86_64拷到u盘上
3. 找个CENTOS装机盘选择手动安装，等到出来安装程序界面的时候，按ctrl
+alt+f2切出一个终端
4. 插入第2步的u盘，并挂载u盘。把刚才拷的anaconda编译出来anaconda-21.48.22.158里的内容拷到根目录。
5. 运行/usr/share/anaconda/restart-anaconda。会重启anaconda
```
比较推荐真机调试，即可以看界面也可以看真实的安装过程。如果只是改pyanaconda，在真机上改了之后，直接运行/usr/share/anaconda/restart-anaconda就可以立即生效。

3.制作成镜像调试

最终安装程序还是要放在镜像里用的，主要是放在squashfs里。
```
1.将LiveOS/squashfs.img拷到本地
2.unsquashfs squashfs.img
3.mkdir tmp && mount -o loop,rw squashfs-root/LiveOS/rootfs.img tmp
3.rpmbuild -bi ~/rpmbuild/SPEC/anaconda.spec
4.cp ~/rpmbuild/BUILDROOT/anaconda-21.48.22.158-1.el7.x86_64/* tmp -rf
5.umount tmp
6.mksquashfs squashfs-root/
7.制作ISO镜像
```
