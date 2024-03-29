using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;

namespace AntiXSSTest
{
    [TestFixture]
    public class TestValidHtml
    {
 
        [Test]
        public void TestHtml_comment()
        {
            TestHelper.RunExpression(
               "<!--This is a comment. Comments are not displayed in the browser-->",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        //[Test]
        //public void TestHtml_declaration()
        //{
        //    TestHelper.RunExpression(
        //       "<!DOCTYPE HTML PUBLIC \" -//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\"> ",
        //       PolicyLoader.Load("actv"),
        //       0,
        //       null);
        //}

        [Test]
        public void TestHtml_a_href()
        {
            TestHelper.RunExpression(
               "<a href=\"http://www.w3schools.com\">Visit W3Schools.com!</a>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<a href=\"test/test/test.html\">Visit W3Schools.com!</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }




        [Test]
        public void TestHtml_a_hreflang()
        {
            TestHelper.RunExpression(
               "<a href=\"http://www.w3school.com.cn\" hreflang=\"zh\">W3School</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_name()
        {
            TestHelper.RunExpression(
               "<a name=\"C4\">Chapter 4</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

      

   

        [Test]
        public void TestHtml_a_shape()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" shape=\"rect\" coords=\"0,0,82,126\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_class()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" class=\"important\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_id()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" id=\"myHeader\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_style()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" style=\"color:green\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtml_a_title()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" title=\"Free Web tutorials\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_dir()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" dir=\"rtl\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_lang()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" lang=\"fr\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_accesskey()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" accesskey=\"h\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_a_tabindex()
        {
            TestHelper.RunExpression(
               "<a href=\"sun.htm\" tabindex=\"2\">The Sun</a>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_abbr()
        {
            TestHelper.RunExpression(
               "<abbr title=\"etcetera\">etc.</abbr>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_acronym()
        {
            TestHelper.RunExpression(
               "<acronym title=\"World Wide Web\">WWW</acronym>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_address()
        {
            TestHelper.RunExpression("<address> Written by W3Schools.com<br /><a href=\"mailto:us@example.org\">Email us</a><br />Address: Box 564, Disneyland<br />Phone: +12 34 56 78</address>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }



        [Test]
        public void TestHtml_area()
        {
            TestHelper.RunExpression(
               "<area shape=\"circle\" coords=\"180,139,14\" href =\"venus.html\" alt=\"Venus\" target =\"_blank\" />",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_b()
        {
            TestHelper.RunExpression(
               "<b>Bold text</b>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_tt()
        {
            TestHelper.RunExpression(
               "<tt>Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_i()
        {
            TestHelper.RunExpression(
               "<i>Italic text</i>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_big()
        {
            TestHelper.RunExpression(
               "<big>Big text</big>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }


        [Test]
        public void TestHtml_bdo()
        {
            TestHelper.RunExpression(
               "<bdo dir=\"rtl\">Here is some Hebrew text!</bdo>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_blockquote()
        {
            TestHelper.RunExpression(
               "<blockquote cite=\"http://www.wwf.org\">Here is a long quotation here is a long quotation here is a long quotation here is a long quotation here is a long quotation here is a long quotation here is a long quotation here is a long quotation here is a long quotation.</blockquote>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }



        [Test]
        public void TestHtml_br()
        {
            TestHelper.RunExpression(
               "<br/>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }




        [Test]
        public void TestHtml_caption()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><caption align=\"bottom\">Monthly savings</caption><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_center()
        {
            TestHelper.RunExpression(
               "<center>This text will be center-aligned.</center>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_em()
        {
            TestHelper.RunExpression(
               "<em>Emphasized text</em>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_strong()
        {
            TestHelper.RunExpression(
               "<strong>Strong text</strong>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }


        [Test]
        public void TestHtml_dfn()
        {
            TestHelper.RunExpression(
               "<dfn>Definition term</dfn>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_code()
        {
            TestHelper.RunExpression(
               "<code>A piece of computer code</code>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_samp()
        {
            TestHelper.RunExpression(
               "<samp>Sample output from a computer program</samp>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_kbd()
        {
            TestHelper.RunExpression(
               "<kbd>Keyboard input</kbd>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_var()
        {
            TestHelper.RunExpression(
               "<var>Variable</var>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_cite()
        {
            TestHelper.RunExpression(
               "<cite>Citation</cite>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_col()
        {
            TestHelper.RunExpression(
               "<col span=\"2\" style=\"background-color:red\" width=\"100\" align=\"left\" valign=\"top\" />",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_colgroup()
        {
            TestHelper.RunExpression(
               "<colgroup span=\"2\" style=\"background-color:#FF0000;\" align=\"right\" width=\"100\" align=\"left\" valign=\"top\"></colgroup>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_dd()
        {
            TestHelper.RunExpression(
               "<dl><dt>Coffee</dt><dd>- black hot drink</dd><dt>Milk</dt><dd>- white cold drink</dd></dl>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }


        [Test]
        public void TestHtml_del()
        {
            TestHelper.RunExpression(
               "<p>My favorite color is <del datetime=\"2009-08-08T21:55:06Z\" cite=\"why_deleted.htm\">blue</del></p>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_dir()
        {
            TestHelper.RunExpression(
               "<dir><li>html</li><li>xhtml</li><li>css</li></dir>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_div()
        {
            TestHelper.RunExpression(
               "<div  style=\"color:blue\" align=\"center\"><h3>This is a header</h3><p>This is a paragraph.</p></div>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        [Test]
        public void TestHtml_dl()
        {
            TestHelper.RunExpression(
               "<dl><dt>Coffee</dt><dd>- black hot drink</dd><dt>Milk</dt><dd>- white cold drink</dd></dl>",
               PolicyLoader.Load("actv"),
               0,
              null);
        }

        public void TestHtml_fieldsetAndlegend()
        {

            TestHelper.RunExpression(
                "<fieldset><legend>Personalia:</legend></fieldset>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_font_color()
        {

            TestHelper.RunExpression(
                "<font color=\"#ffcc00\">This is some text!</font>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }


        [Test]
        public void TestHtml_font_face()
        {
            
            TestHelper.RunExpression(
                "<font face=\"verdana\">This is some text!</font>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_font_size()
        {
            
            TestHelper.RunExpression(
                "<font size=\"5\">This is some text!</font>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }


        [Test]
        public void TestHtml_h16()
        {

            TestHelper.RunExpression(
                "<h1>This is heading 1</h1><h2>This is heading 1</h2><h3>This is heading 1</h3><h4>This is heading 1</h4><h5>This is heading 1</h5><h6>This is heading 1</h6>",
                PolicyLoader.Load("actv"),
                0,
                null);

        }

        [Test]
        public void TestHtml_h1_align()
        {
            //Deprecated
            TestHelper.RunExpression(
                "<h1 align=\"center\">This is heading 1</h1>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }


        [Test]
        public void TestHtml_hr()
        {

            TestHelper.RunExpression(
                "<p>This is some text.</p><hr /><p>This is some text.</p> ",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_hr_align()
        {
            //Deprecated: width, align
            TestHelper.RunExpression(
                "<hr align=\"center\" width=\"50%\" />",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_hr_noshade()
        {
            //Deprecated
            TestHelper.RunExpression(
                "<hr noshade=\"noshade\" />",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_hr_size()
        {
            //Deprecated   
            TestHelper.RunExpression(
                "<hr size=\"50\" />",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_hr_width()
        {
            //Deprecated
            TestHelper.RunExpression(
                "<hr width=\"50%\" />",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_img_srcAlt()
        {
            TestHelper.RunExpression(
               "<img src=\"smiley.gif\" alt=\"Smiley face\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtml_img_align()
        {

            TestHelper.RunExpression(
               "<img src=\"/i/eg_cute.gif\" align=\"middle\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_img_border()
        {
            TestHelper.RunExpression(
               "<img src=\"/i/eg_logo_w3school.gif\" border=\"1\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_img_heightWidth()
        {
            TestHelper.RunExpression(
               "<img src=\"/i/mouse.jpg\" height=\"200\" width=\"200\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_img_hspaceVspace()
        {
            TestHelper.RunExpression(
               "<img src=\"w3school.gif\" hspace=\"30\" vspace=\"30\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_img_ismap()
        {
            TestHelper.RunExpression(
               "<img src=\"tulip.gif\" ismap=\"ismap\" />",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_img_usemap()
        {
            TestHelper.RunExpression(
               "<img usemap=\"#value\">",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtml_ins()
        {
            TestHelper.RunExpression(
                "My favorite color is<ins>red</ins>!",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_ins_cite()
        {
            
            TestHelper.RunExpression(
                "My favorite color is<ins cite=\"why_inserted.htm\">red</ins>!",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_ins_datetime()
        {
            TestHelper.RunExpression(
                "My favorite color is<ins datetime=\"2009-08-08T21:55:06Z\">red</ins>!",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestHtml_lable()
        {

            TestHelper.RunExpression(
                "<label for=\"male\">Male</label>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_lable_for()
        {
            
            TestHelper.RunExpression(
                "<label for=\"male\">Male</label>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_li()
        {

            TestHelper.RunExpression(
                "<li>Coffee</li>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }


        [Test]
        public void TestHtml_li_type()
        {
            //Deprecated
            TestHelper.RunExpression(
                "<li type=\"a\">Coffee</li>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml_li_value()
        {
            //Deprecated
            TestHelper.RunExpression(
                "<li value=\"100\">Coffee</li>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }


        [Test]
        public void TestHtm_map()
        {
            TestHelper.RunExpression(
               "<map></map>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_map_name()
        {
            TestHelper.RunExpression(
               "<map name=\"planetmap\"></map>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_menu()
        {
            TestHelper.RunExpression(
               "<menu><li>html</li><li>xhtml</li><li>css</li></menu>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtm_noframes()
        {
            TestHelper.RunExpression(
               "<noframes>Sorry, your browser does not handle frames!</noframes>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        // <script type=\"text/javascript\">document.write(\"Hello World!\")</script>
        [Test]
        public void TestHtm_noscript()
        {
            TestHelper.RunExpression(
               "<noscript>Your browser does not support JavaScript!</noscript>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtm_ol()
        {
            TestHelper.RunExpression(
               "<ol><li>Coffee</li><li>Tea</li><li>Milk</li></ol>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

       
        


        [Test]
        public void TestHtm_ol_start()
        {
            TestHelper.RunExpression(
               "<ol start=\"5\"><li>HTML</li><li>XHTML</li><li>CSS</li></ol>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ol_type()
        {
            TestHelper.RunExpression(
               "<ol type=\"I\"><li>HTML</li><li>XHTML</li><li>CSS</li></ol>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_p()
        {
            TestHelper.RunExpression(
               "<p>This is some text in a very short paragraph</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_p_align()
        {
            TestHelper.RunExpression(
               "<p align=\"right\">This is some text in a very short paragraph</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_pre()
        {
            TestHelper.RunExpression(
               "<pre>Text in a pre elementfont, and it preservesboth      spaces andline breaks</pre>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        
      
        [Test]
        public void TestHtm_q()
        {
            TestHelper.RunExpression(
               "<q>Here is a short quotation here is a short quotation</q>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_q_cite()
        {
            TestHelper.RunExpression(
               "<q cite=\"http://www.wwf.org\">Here is a short quotation here is a short quotation</q>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_s()
        {
            TestHelper.RunExpression(
               "<p>Version 2.0 is <s>not yet available!</s> now available!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_samp()
        {
            TestHelper.RunExpression(
               "<samp>Sample output from a computer program</samp>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_small()
        {
            TestHelper.RunExpression(
               "<small>Small text</small>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_span()
        {
            TestHelper.RunExpression(
               "<p>My mother has <span style=\"color:blue\">light blue</span> eyes.</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_strike()
        {
            TestHelper.RunExpression(
               "<p>Version 2.0 is <strike>not yet available!</strike> now available!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_strong()
        {
            TestHelper.RunExpression(
               "<strong>Strong text</strong>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        // <html><head><style type=\"text/css\">h1 {color:red;}p {color:blue;}</style></head><body><h1>Header 1</h1><p>A paragraph.</p></body></html>
        [Test]
        public void TestHtm_style()
        {
            TestHelper.RunExpression(
               "<style type=\"text/css\">h1 {color:red;}p {color:blue;}</style><h1>Header 1</h1><p>A paragraph.</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

   

        [Test]
        public void TestHtm_style_media()
        {
            TestHelper.RunExpression(
               "<style type=\"text/css\" media=\"print\">h1 {color:red;}p {color:blue;}</style><h1>Header 1</h1><p>A paragraph.</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_sub()
        {
            TestHelper.RunExpression(
               "<p>This text contains <sub>subscript</sub> text.</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_sup()
        {
            TestHelper.RunExpression(
               "<p>This text contains <sup>superscript</sup> text.</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_table()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_table_allattributes()
        {
            TestHelper.RunExpression(
               "<table border=\"1\" align=\"right\" bgcolor=\"#FF0000\" cellpadding=\"10\" cellpadding=\"10\" frame=\"box\" rules=\"rows\" summary=\"Monthly\" width=\"40%\"><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tbody()
        {
            TestHelper.RunExpression(
   "<body>",
   PolicyLoader.Load("actv"),
   0,
   null);
            TestHelper.RunExpression(
               "<table border=\"1\"><thead><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tbody_allattributes()
        {
            //charoff: no support in browsers
            TestHelper.RunExpression(
               "<table border=\"1\"><thead><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody align=\"left\" char=\"M\" charoff=\"2\" valign=\"middle\"><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_td()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        

        [Test]
        public void TestHtm_td_allattributes()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr><td abbr=\"Company\" align=\"right\" axis=\"name\" bgcolor=\"#FF0000\" char=\"C\" charoff=\"2\" colspan=\"2\" headers=\"value\" height=\"100px\" nowrap=\"nowrap\" scope=\"col\" valign=\"middle\" width=\"40%\">January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tfoot()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tfoot_allattributes()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead><tr><th>Month</th><th>Savings</th></tr></thead><tfoot align=\"center\" char=\".\" charoff=\"2\" valign=\"bottom\"><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_th()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

       
        [Test]
        public void TestHtm_th_allattributes()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th abbr=\"Company\" align=\"right\" axis=\"name\" bgcolor=\"#FF0000\" char=\"C\" charoff=\"2\" colspan=\"2\" headers=\"value\" height=\"100px\" nowrap=\"nowrap\" scope=\"col\" valign=\"middle\" width=\"40%\">Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_thead()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_thead_align()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead align=\"left\"><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        
        [Test]
        public void TestHtm_thead_char()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead char=\"M\"><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_thead_charoff()
        {
            //no browser support
            TestHelper.RunExpression(
               "<table border=\"1\"><thead charoff=\"2\"><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_thead_valign()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><thead valign=\"middle\"><tr><th>Month</th><th>Savings</th></tr></thead><tfoot><tr><td>Sum</td><td>$180</td></tr></tfoot><tbody><tr><td>January</td><td>$100</td></tr><tr><td>February</td><td>$80</td></tr></tbody></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tr()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tr_align()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr align=\"center\"><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tr_bgcolor()
        {
            //Deprecated
            TestHelper.RunExpression(
               "<table border=\"1\"><tr><th>Month</th><th>Savings</th></tr><tr bgcolor=\"#FF0000\"><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tr_char()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr char=\".\"><th>Month</th><th>Savings</th></tr><tr bgcolor=\"#FF0000\"><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tr_charoff()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr charoff=\"2\"><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtm_tr_valign()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr valign=\"middle\"><th>Month</th><th>Savings</th></tr><tr bgcolor=\"#FF0000\"><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        #region tt tag
        [Test]
        public void TestHtm_tt()
        {
            TestHelper.RunExpression(
               "<tt>Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tt_class()
        {
            TestHelper.RunExpression(
               "<tt class=\"intro\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tt_id()
        {
            TestHelper.RunExpression(
               "<tt id=\"myHeader\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tt_style()
        {
            TestHelper.RunExpression(
               "<tt style=\"color:red\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_tt_title()
        {
            TestHelper.RunExpression(
               "<tt title=\"People Republic of China\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_tt_dir()
        {
            TestHelper.RunExpression(
               "<tt dir=\"rtl\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_tt_lang()
        {
            TestHelper.RunExpression(
               "<tt lang=\"fr\">Teletype text</tt>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        #endregion

        #region u tag
        [Test]
        public void TestHtm_u()
        {
            TestHelper.RunExpression(
               "<p>Do not <u>underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_u_class()
        {
            TestHelper.RunExpression(
               "<p>Do not <u class=\"intro\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_u_id()
        {
            TestHelper.RunExpression(
               "<p>Do not <u id=\"myHeader\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_u_style()
        {
            TestHelper.RunExpression(
               "<p>Do not <u style=\"color:red\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_u_title()
        {
            TestHelper.RunExpression(
               "<p>Do not <u title=\"People Republic of China\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_u_dir()
        {
            TestHelper.RunExpression(
               "<p>Do not <u dir=\"rtl\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_u_lang()
        {
            TestHelper.RunExpression(
               "<p>Do not <u lang=\"fr\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtm_u_xmllang()
        {
            TestHelper.RunExpression(
               "<p>Do not <u xml:lang=\"en\">underline</u> text if it is not a hyperlink!</p>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        #endregion

        #region ul tag
        [Test]
        public void TestHtm_ul()
        {
            TestHelper.RunExpression(
               "<ul><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
                
       

        [Test]
        public void TestHtm_ul_type()
        {
            //Deprecated
            TestHelper.RunExpression(
               "<ul type=\"square\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);        
        }

        [Test]
        public void TestHtm_ul_class()
        {
            TestHelper.RunExpression(
               "<ul class=\"intro\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ul_id()
        {
            TestHelper.RunExpression(
               "<ul id=\"intro\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ul_style()
        {
            TestHelper.RunExpression(
               "<ul style=\"color:red\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ul_title()
        {
            TestHelper.RunExpression(
               "<ul title=\"People Republic of China\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }


        [Test]
        public void TestHtm_ul_dir()
        {
            TestHelper.RunExpression(
               "<ul dir=\"rtl\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ul_lang()
        {
            TestHelper.RunExpression(
               "<ul lang=\"fr\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_ul_xmllang()
        {
            TestHelper.RunExpression(
              "<ul xml:lang=\"en\"><li>Coffee</li><li>Tea</li><li>Milk</li></ul>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        #endregion

        #region var tag
        [Test]
        public void TestHtm_var()
        {
            TestHelper.RunExpression(
               "<var>Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_class()
        {
            TestHelper.RunExpression(
               "<var class=\"intro\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_id()
        {
            TestHelper.RunExpression(
               "<var id=\"myHeader\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_style()
        {
            TestHelper.RunExpression(
               "<var style=\"color:red\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_title()
        {
            TestHelper.RunExpression(
               "<var title=\"People Republic of China\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
       

        [Test]
        public void TestHtm_var_dir()
        {
            TestHelper.RunExpression(
               "<var dir=\"rtl\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_lang()
        {
            TestHelper.RunExpression(
               "<var lang=\"fr\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtm_var_xmllang()
        {
            TestHelper.RunExpression(
               "<var xml:lang=\"en\">Variable</var>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        #endregion
    }
}