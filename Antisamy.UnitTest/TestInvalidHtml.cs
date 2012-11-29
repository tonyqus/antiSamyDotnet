using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using org.owasp.validator.html.util;

namespace AntiXSSTest
{
    [TestFixture]
    public class TestInvalidHtml
    {
        [Test]
        public void TestHtml_script_alert()
        {
            TestHelper.RunExpression(
               "<script>alert(1)</script>",
               PolicyLoader.Load("actv"),
               1,
                new string[] { ("<script>") });
        }

        [Test]
        public void TestHtml_a_rev()
        {
            TestHelper.RunExpression(
               "<a rev=\"friend\" href=\"http://www.functravel.com/\">Cheap Flights</a>",
               PolicyLoader.Load("actv"),
               1,
                new string[] { ("rev") });
        }

        [Test]
        public void TestHtml_a_rel()
        {
            TestHelper.RunExpression(
               "<a rel=\"friend\" href=\"http://www.functravel.com/\">Cheap Flights</a>",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("rel") });
        }


        [Test]
        public void TestHtml_a_charset()
        {
            //no support in any browser
            TestHelper.RunExpression(
               "<a charset=\"gb2312\" href=\"http://www.w3school.com.cn\">www.W3School.com.cn</a>",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("charset") });
        }

        [Test]
        public void TestHtm_ul_compact()
        {
            //Deprecated
            TestHelper.RunExpression(
               "<ul compact=\"compact\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               1,
               new string[] { ("compact") });
        }

        [Test]
        public void TestHtm_pre_width()
        {
            //Deprecated
            TestHelper.RunExpression(
               "<pre width=\"40%\">Text in a pre elementfont, and it preservesboth      spaces andline breaks</pre>",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("width") });
        }

        [Test]
        public void TestHtm_ol_compact()
        {
            TestHelper.RunExpression(
               "<ol compact=\"compact\" start=\"5\" type=\"I\"><li>Coffee</li><li>Tea</li><li>Milk</li></ol>",
               PolicyLoader.Load("actv"),
               1,
                new string[] { ("compact") });
        }


        [Test]
        public void TestHtml_input()
        {
            TestHelper.RunExpression(
               "First name: <input type=\"text\" name=\"FirstName\" value=\"Mickey\" />",
               PolicyLoader.Load("actv"),
               1,
               new string[] { ("<input>") });
        }
        [Test]
        public void TestHtml_link()
        {
            TestHelper.RunExpression(
                "<link rel=\"stylesheet\" type=\"text/css\" href=\"styles.css\" >I am formatted with a linked style sheet",
                PolicyLoader.Load("actv"),
                1,
                new string[] { ("<link>") });
        }
        [Test]
        public void TestHtm_object()
        {
            TestHelper.RunExpression(
               "<object width=\"400\" height=\"400\" data=\"helloworld.swf\"></object>",
               PolicyLoader.Load("actv"),
               1,
               new string[] { ("<object>") });
        }

        [Test]
        public void TestHtm_param()
        {
            TestHelper.RunExpression(
               "<object data=\"horse.wav\"><param name=\"autoplay\" value=\"false\" /></object>",
               PolicyLoader.Load("actv"),
               2,
               new string[] { ("<object>"),("<param>") });
        }
        [Test]
        public void TestHtm_script()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\" language=\"javascript\">document.write(\"Hello World!\")</script>",
               PolicyLoader.Load("actv-medium"),
               1,
               new string[] { ("document.write") });
        }


        [Test]
        public void TestHtm_textarea()
        {
            TestHelper.RunExpression(
               "<textarea rows=\"2\" cols=\"20\">Test</textarea>",
               PolicyLoader.Load("actv"),
               1,
               new string[] { ("<textarea>") });
        }
        [Test]
        public void TestHtm_select()
        {
            TestHelper.RunExpression(
               "<select><optgroup label=\"Swedish Cars\"><option value =\"volvo\">Volvo</option><option value =\"saab\">Saab</option></optgroup></select>",
               PolicyLoader.Load("actv"),
               3,
               new string[] { ("<select>"), ("<optgroup>"), ("<option>") });
        }


        [Test]
        public void TestHtml_iframe()
        {
            TestHelper.RunExpression(
                "<iframe src=\"http://www.baidu.com\"></iframe> ",
                PolicyLoader.Load("actv"),
                1,
                new string[] { ("<iframe>") });
        }

        [Test]
        public void TestHtm_meta()
        {
            TestHelper.RunExpression(
               "<meta name=\"description\" content=\"Free Web tutorials\" />",
               PolicyLoader.Load("actv"),
                1,
                new string[] { ("<meta>") });
        }


        [Test]
        public void TestHtml_form() //---------------------invaild
        {
            TestHelper.RunExpression(
                "<form>First name:serena </form>",
                PolicyLoader.Load("actv"),
                1,
                new string[] { ("<form>") });
        }
        [Test]
        public void TestHtml_frameANDframeset()//--------------------------------------------------------------invaild
        {
            TestHelper.RunExpression(
                 "<frameset><frame src=\"frame_a.htm\" /></frameset>",
                 PolicyLoader.Load("actv"),
                1,
                new string[] { ("<frameset>") });
        }
        [Test]
        public void TestHtml_htmlandhead()//--------------------------------------------------------------invaild
        {
            TestHelper.RunExpression(
                "<html><head>hello£¡</head></html>",
                PolicyLoader.Load("actv"),
                2,
                new string[] { ("<html>"), ("<head>") });
        }

        [Test]
        public void TestHtml_button()
        {
            TestHelper.RunExpression(
               "<button type=\"button\">Click Me!</button>",
               PolicyLoader.Load("actv"),
              1,
              new string[] { ("<button>") });
        }

        [Test]
        public void TestHtml_body()
        {
            TestHelper.RunExpression(
               "<body>The content of the document......</body>",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("<body>") });
        }
        [Test]
        public void TestHtm_title()
        {
            TestHelper.RunExpression(
               "<html><head><title>HTML 4.01 Tag Reference</title></head><body>The content of the document......</body></html>",
               PolicyLoader.Load("actv"),
               4,
               new string[] { ("<html>"),
                   ("<head>"),
                   ("<title>"),
                   ("<body>") });
        }
        [Test]
        public void TestHtml_applet()
        {
            TestHelper.RunExpression(
               "<applet code=\"Bubbles.class\" width=\"350\" height=\"350\">Java applet that draws animated bubbles.</applet>",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("<applet>") });
        }

        [Test]
        public void TestHtml_base()
        {
            TestHelper.RunExpression(
               "<base href=\"http://www.w3schools.com/images/\" target=\"_blank\" />",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("<base>") });
        }

        [Test]
        public void TestHtml_basefont()
        {
            TestHelper.RunExpression(
               "<basefont color=\"red\" size=\"5\" />",
               PolicyLoader.Load("actv"),
               1,
              new string[] { ("<basefont>") });
        }


        [Test]
        public void TestJS_documentcookie()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">alert(document.cookie)</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("document.cookie") });
        }

        [Test]
        public void TestJS_documentwrite()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">document.write(document.cookie)</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("document.write") });
        }

        [Test]
        public void TestJS_locationhref()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">document.writeln(location.href);</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("location.href") });
        }


        [Test]
        public void TestJS_XMLHttpRequest()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">function sendRequest(){var xmlHttpReq=init();function init(){¡¡if (window.XMLHttpRequest) {¡¡return new XMLHttpRequest();} else if (window.ActiveXObject) {return new ActiveXObject(\"Microsoft.XMLHTTP\");}}</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("XMLHttpRequest") });
        }

        [Test]
        public void TestJS_ActiveXObject()
        {
            TestHelper.RunExpression(
              "<script type=\"text/javascript\">function sendRequest(){var xmlHttpReq=init();function init(){if (window.ActiveXObject) {return new ActiveXObject(\"Microsoft.XMLHTTP\");}}</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("ActiveXObject") });
        }

        [Test]
        public void TestJS_Eval()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">eval(\"x=10;y=20;document.write(x*y)\")document.write(eval(\"2+2\"))var x=10document.write(eval(x+17))</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("eval(") });
        }


        [Test]
        public void TestJS_documentcreateElement()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">var board = document.getElementById(\"board\");var e = document.createElement(\"input\");e.type = \"button\";e.value = \"Test\";var object = board.appendChild(e);</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { ("document.createElement(") });
        }

    
        
        [Test]
        public void TestJS_appendChild()
        {
            TestHelper.RunExpression(
               "<script language=\"javascript\"> function newElement(){var newElem;  newElem.setAttribute(\"id\",\"newP\"); var newText = document.createTextNode(\"This is the second paragraph.\");  newElem.appendChild(newText);   for(var i=0;i<5;i++) document.getElementById(\"paragraph1\").appendChild(newElem);   } </script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".appendChild(") });
        }

        [Test]
        public void TestJS_insertBefore()
        {
            TestHelper.RunExpression(
               "<script language=\"javascript\">xmlDoc.documentElement.insertBefore(newNode,get_lastchild(x));</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".insertBefore(") });
        }

        [Test]
        public void TestJQ_append()
        {
            TestHelper.RunExpression(
               "<script>$(\"p\").append(\"<strong>Hello</strong>\");</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".append(") });
        }


        [Test]
        public void TestJQ_ajax()
        {
            TestHelper.RunExpression(
               "<script>$.ajax({url: a_cross_domain_url, xhrFields: {withCredentials: true}});</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".ajax(") });
        }

        [Test]
        public void TestJQ_getScript()
        {
            TestHelper.RunExpression(
               "<script>$.getScript(\"/scripts/jquery.color.js\",function() {$(\"#go\").click(function(){$(\".block\").animate( { backgroundColor: \"pink\" }, 1000) .delay(500) .animate( { backgroundColor: \"blue\" }, 1000);});});</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".getScript(") });
        }

        [Test]
        public void TestJQ_load()
        {
            TestHelper.RunExpression(
               "<script>$(\"#new-nav\").load(\"/ #jq-footerNavigation li\");</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".load(") });
        }

        [Test]
        public void TestJQ_get()
        {
            TestHelper.RunExpression(
               "<script>$.get(\"test.php\");</script>",
               PolicyLoader.Load("actv-medium"),
               1,
              new string[] { (".get(") });
        }
    }
}
