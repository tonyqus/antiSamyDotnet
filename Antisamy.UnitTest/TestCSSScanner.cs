using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using OWASP = org.owasp.validator.html;
using org.owasp.validator.html.util;

namespace AntiXSSTest
{

    [TestFixture]
    public class TestCSSScanner
    {
        [Test]
        public void TestXmlDeclarationWithOmitXml_True()
        {
            TestHelper.RunExpression(
               "<font style=\"font-size: 12px; font-family: Arial\">test</font><xml><o:p></o:p><w:WordDocument><w:View>Normal</w:View><w:Zoom>0</w:Zoom><w:TrackMoves/><w:TrackFormatting/><w:PunctuationKerning/>",
                PolicyLoader.Load("actv"),
                0,
                null);
            TestHelper.RunExpression(
               "<P>&nbsp;</P></FONT></SPAN><SPAN style=\"FONT-SIZE: 10pt; FONT-FAMILY: Arial\"><?xml:namespace prefix = o ns = \"urn:schemas-microsoft-com:office:office\" /><o:p></o:p></SPAN></FONT>",
                PolicyLoader.Load("actv"),
                0,
                null);

        }
        [Test]
        public void TestXmlDeclarationWithOmitXml_False()
        {
            TestHelper.RunExpression(
               "<font style=\"font-size: 12px; font-family: Arial\">test</font><xml><o:p></o:p><w:WordDocument><w:View>Normal</w:View><w:Zoom>0</w:Zoom><w:TrackMoves/><w:TrackFormatting/><w:PunctuationKerning/>",
                PolicyLoader.Load("ebay"),
                8,
                new string[] 
                {
                    "<xml>",
                    "<o:p>",
                    "<w:worddocument>",
                    "<w:view>",
                    "<w:zoom>",
                    "<w:trackmoves>",
                    "<w:trackformatting>",
                    "<w:punctuationkerning>"
                });
        }
        [Test]
        public void TestMsoStylesWithOmitSettings_True()
        {
            TestHelper.RunExpression(
               "<p style=\"margin: 5pt 10.5pt; text-indent: 20pt; mso-para-margin-top: 5.0pt; mso-para-margin-right: 1.0gd; mso-para-margin-bottom: 5.0pt; mso-para-margin-left: 1.0gd; mso-char-indent-count: 2.0\"><span style=\"font-size: 10pt\"><font style=\"font-size: 12px; font-family: Arial\">test</font>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestMsoStylesWithOmitSettings_False()
        {
            TestHelper.RunExpression(
               "<p style=\"margin: 5pt 10.5pt; text-indent: 20pt; mso-para-margin-top: 5.0pt; mso-para-margin-right: 1.0gd; mso-para-margin-bottom: 5.0pt; mso-para-margin-left: 1.0gd; mso-char-indent-count: 2.0\"><span style=\"font-size: 10pt\"><font style=\"font-size: 12px; font-family: Arial\">test</font>",
                PolicyLoader.Load("ebay"),
                1,
                new string[] { ("margin:5pt 10.5pt;mso-para-margin-top:5.0pt;mso-para-margin-right:1.0gd;mso-para-margin-bottom:5.0pt;mso-para-margin-left:1.0gd;mso-char-indent-count:2.0;") });
        }
        [Test]
        public void TestInlineStyle()
        {
            TestHelper.RunExpression(
               "<P><SPAN style=\"FONT-SIZE: 12pt; mso-bidi-font-size: 10.0pt;width:expression(body.width)\">Jie Qu</SPAN></P>",
                PolicyLoader.Load("actv"),
                1,
                new string[] { ("width:expression(body.width);") });
        }

        [Test]
        public void TestCSSBlacklist1()
        {
            TestHelper.RunExpression(
                "<STYLE TYPE=\"text/css\" MEDIA=\"screen\">BODY{ background: url(foo.gif) red; color: black; width:expression(test.width) }</STYLE>",
                PolicyLoader.Load("actv"),
                1,
                new string[] { (":expression(") });
        }
        [Test]
        public void TestCSSBlacklist2()
        {
            TestHelper.RunExpression(
                "<STYLE TYPE=\"text/css\" MEDIA=\"screen\">BODY{ background: url(foo.gif) red; color: black; width:+ADw-script+AD4-alert(+ACc-utf-7!+ACc-)+ADw-+AC8-script+AD4- }</STYLE>",
                PolicyLoader.Load("actv"),
                1,
                new string[] { ("+ADw-") });
        }

        #region CSS STYLE
        [Test]
        public void TestHtm_backgroundCss_valign()
        {
            TestHelper.RunExpression(
               "<div style=\"background:#ff0000 url(/i/eg_bg_03.gif) no-repeat fixed center;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<div style=\"background-color:#ff0000;background-image:url(/i/eg_bg_02.gif);background-repeat:no-repeat;background-attachment:fixed;background-position:center; \">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }



        [Test]
        public void TestHtm_borderCss_valign()
        {
            TestHelper.RunExpression(
               "<div style=\"border:medium double rgb(250,0,255)\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
                "<div style=\"border-style:solid;border-bottom:thick dotted #ff0000;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
                "<div style=\"border-style:solid;border-bottom-color:#ff0000;border-bottom-style:dotted;border-bottom-width:15px;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<div style=\"border-color:red green blue pink;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<div style=\"border-left:thick double #ff0000;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
                "<div style=\"border-left-color: #ff0000;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div style=\"border-left-style:dotted;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div style=\"border-left-width:15px;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div style=\"border-right:thick double #ff0000;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-right-color:#ff0000;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-right-style:dotted;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div style=\"border-right-width:15px;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div style=\"border-style:dotted solid double dashed;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-top:thick double #ff0000;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-top-color:#ff0000;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-top-style:dotted;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-top-width:15px;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-width:thin medium thick 10px;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"border-width:thin medium thick 10px;\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


        }

        [Test]
        public void TestHtm_outlineCss_valign()
        {
            TestHelper.RunExpression(
               "<div style=\"border:red solid thin;outline:#00ff00 dotted thick;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<div style=\"border:red solid thin;outline-color:#00ff00;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);


            TestHelper.RunExpression(
               "<div style=\"border:red solid thin;outline-style:dotted;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);


            TestHelper.RunExpression(
               "<div style=\"border:red solid thin;outline-width:5px;\">Albert</div>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_colorCss_valign()
        {

            TestHelper.RunExpression(
                "<div style=\"color:red\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div style=\"color:red;direction:rtl\">Albert</div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><h1 style=\"letter-spacing:-0.5em\">Albert</h1></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"line-height:90%\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><h1 style=\"text-align:center\">Albert</h1></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><h1 style=\"text-decoration:overline\">Albert</h1></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"text-indent:50px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"text-transform:uppercase;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"white-space: nowrap;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"word-spacing: 30px;\">Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

        }

        [Test]
        public void TestHtm_FontCss_valign()
        {

            TestHelper.RunExpression(
                "<div><p style=\"font:italic arial,sans-serif;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-family:'Times New Roman',Georgia,Serif\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-size:250%;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-size-adjust:0.58;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-stretch:ultra-condensed;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-style:italic;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-variant:small-caps;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"font-weight:bold;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


        }

        [Test]
        public void TestHtm_MarginCss_valign()
        {

            TestHelper.RunExpression(
                "<div><p style=\"margin: 2cm 4cm 3cm 4cm\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"margin-bottom:2cm;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"margin-left:2cm;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"margin-right:2cm;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"margin-top:2cm;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

        }

        [Test]
        public void TestHtm_PaddingCss_valign()
        {
            
            TestHelper.RunExpression(
                "<div><td style=\"padding:10px 5px 15px 20px;\">Albert albert Albert albert</td></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

                        
            TestHelper.RunExpression(
                "<div><td style=\"padding-bottom:2cm;\">Albert albert Albert albert</td></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><td style=\"padding-left:2cm;\">Albert albert Albert albert</td></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><td style=\"padding-right:2cm;\">Albert albert Albert albert</td></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><td style=\"padding-top:2cm;\">Albert albert Albert albert</td></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


        }

        [Test]
        public void TestHtm_ListCss_valign()
        {

            TestHelper.RunExpression(
                "<div><ul style=\"list-style: square inside url('/i/eg_arrow.gif')\"><li>咖啡</li><li>茶</li><li>可口可乐</li></ul></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><ul style=\"list-style-image: url('/i/eg_arrow.gif')\"><li>咖啡</li><li>茶</li><li>可口可乐</li></ul></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p>该列表的 list-style-position 的值是 \"inside\"：</p><ul style=\"list-style-position: inside\"><li>咖啡</li><li>茶</li><li>可口可乐</li></ul></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p>Drink circle:</p><ul style=\"list-style-type:circle;\"><li>咖啡</li><li>茶</li><li>可口可乐</li></ul></div>",
                PolicyLoader.Load("actv"),
                0,
                null);



        }



        [Test]
        public void TestHtm_DimensionCss_valign()
        {

            TestHelper.RunExpression(
                "<div><p style=\"max-height:10px\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"max-width:10px\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"min-height:100px;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"min-width:100px;\">Albert albert Albert albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);



        }

        #endregion

        [Test]
        public void TestCSS_Positioning()
        {
            TestHelper.RunExpression(
                "<div><p style=\"bottom:5px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"clear:both;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);


            TestHelper.RunExpression(
                "<div><p style=\"cursor:wait;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"display:inline;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"float:right;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"left:100px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"overflow:scroll;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            
            TestHelper.RunExpression(
                "<div><p style=\"right:5px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            
            TestHelper.RunExpression(
                "<div><p style=\"top:5px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            
            TestHelper.RunExpression(
                "<div><p style=\"vertical-align:text-top;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            
            TestHelper.RunExpression(
                "<div><p style=\"visibility:hidden;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            
            TestHelper.RunExpression(
                "<div><p style=\"z-index:-1;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<div><p style=\"clip:rect(0px,60px,200px,0px);\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
            TestHelper.RunExpression(
                "<div><p style=\"position:absolute;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        

        [Test]
        public void TestCSS_orphans()
        {
            TestHelper.RunExpression(
                "<div><p style=\"orphans: 4;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestCSS_widows()
        {
            TestHelper.RunExpression(
                "<div><p style=\"widows: 3\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestCSS_pagebreakafter()
        {
            TestHelper.RunExpression(
                "<div><p style=\"page-break-after:always;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestCSS_pagebreakbefore()
        {
            TestHelper.RunExpression(
                "<div><p style=\"page-break-before:always;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestCSS_pagebreakinside()
        {
            TestHelper.RunExpression(
                "<div><p style=\"page-break-inside:avoid;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }



        [Test]
        public void TestCSS_bordercollapse()
        {
            TestHelper.RunExpression(
                "<div><p style=\"border-collapse:collapse;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestCSS_borderspacing()
        {
            TestHelper.RunExpression(
                "<div><p style=\"border-spacing:10px 50px;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestCSS_captionside()
        {
            TestHelper.RunExpression(
                "<div><p style=\"caption-side:bottom;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestCSS_emptycells()
        {
            TestHelper.RunExpression(
                "<div><p style=\"empty-cells:hide;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestCSS_tableclayout()
        {
            TestHelper.RunExpression(
                "<div><p style=\"table-layout:fixed;\">Albert</p></div>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
    }
     
    
}
