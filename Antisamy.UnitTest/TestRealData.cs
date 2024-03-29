using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using org.owasp.validator.html.util;
using System.Diagnostics;

namespace AntiXSSTest
{
    [TestFixture]
    public class TestRealData
    {
        [Test]
        public void TestHtml1()
        {
            TestHelper.RunExpression(
                "&nbsp;<h1>Welcome</h1><p><strong>PLEASE NOTE: This website is intended for informational purposes and registration is not available. If you would like to register for the conference, please contact your Morgan Stanley representative.</strong></p><p><strong>Please see the Web Builder Resources site for up-to-date sample html code. </strong></p><p><b>{{Event.Street2}}</b><br />{{Event.Location}}<br />{{Event.Street1}}<br />{{Event.City}} {{Event.Zip}}</p><br />",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml2()
        {
            TestHelper.RunExpression(
                "<h1>セミナーのご案内</h1><p>株式会社は、資産運用や制度に関する少人数制の勉強会、「セミナー」を開講いたします。この度は下記日程・会場におきまして、スポンサーの方々がご理解を深められていたほうが良いと思われる経済用語の基礎知識の他、最近、問い合わせが多くなってきた市場に関連する講座を用意いたしました。ご興味がおありの方々は、是非、ご参加くださいますようお願い申し上げます。また下記以外の他会場での開催も検討していますので、ご希望の開催地域がありましたらご一報くださいますようお願いいたします。基本講座が、皆様に少しでもお役に立てれば幸いです。 <br /><br />&bull;&nbsp;&nbsp;&nbsp;&nbsp; 制度や運用に関する基礎知識が身につく。<br />&bull;&nbsp;&nbsp;&nbsp;&nbsp; 少人数制で、興味のあるテーマや修得したいテーマのみの参加可能。<br />&bull;&nbsp;&nbsp;&nbsp;&nbsp; 少人数制なので、質疑応答がしやすい。<br />&bull;&nbsp;&nbsp;&nbsp;&nbsp; 運用会社のプロが説明するので、要点を掴んだ資料や説明である。<br />&bull;&nbsp;&nbsp;&nbsp;&nbsp; 参加者間の交流のきっかけができる。<br /><br /><br /><br />お申込み・お問い合わせは<br />Tel: (00) 0000 0000<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; (00) 0000 0000 <br />Email: <a href=\"mailto:enquiries.apsummit@morganstanley.com\">test@test.com</a></p>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml3_background_color()
        {
            TestHelper.RunExpression(
                "<p><span style=\"background-color: aqua\">{{Event.Name}}Simple</span></p>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<p><span style=\"background-color: rgb(255,255,123);\">{{Event.Name}}Simple</span></p>",
                PolicyLoader.Load("actv"),
                0,
                null);

            //fix color hex code
            TestHelper.RunExpression(
                "<p><span style=\"background-color: #ff6600\">{{Event.Name}}Simple</span></p>",
                PolicyLoader.Load("actv"),
                0,
                null);

            TestHelper.RunExpression(
                "<p style=\"line-height:12pt;\" class=\"MsoNormal\">",
                PolicyLoader.Load("actv"),
                0,
                null);
        }
        [Test]
        public void TestHtml4()
        {
            //fix a:target attribute
            TestHelper.RunExpression(
                "<span class=\"headercolor\">Welcome</span><p class=\"firstpara\">Goldman Sachs cordially invites you to the <b>Seventh Annual European Medtech and Healthcare Services Conference</b>, taking place 8 and 9 September 2010, at the Goldman Sachs Offices, 120 Fleet Street, London.</p><p class=\"bodytext\">The conference will feature over 27 companies in the medical device and healthcare services sector, ranging from small to large cap and including CEO’s from diagnostic, orthopedic, hearing aid, and dental implant companies, and also from additional sectors within healthcare. We are thrilled that the vast majority of the presentations will be conducted by CEOs.  </p><p class=\"bodytext\">Given the increasing fiscal pressures in many European countries, we will also host a panel discussion focusing on pricing and reimbursement for medical devices and healthcare services across Europe, moderated by Paula Wittels, the Programme Director at the UK-based consultancy Translucency. The panel will comment on proposed and recently enacted European healthcare reforms, and what they will likely mean for the medical device and healthcare service industries, with particular focus on how pricing and reimbursement might change in coming years.</p><p class=\"bodytext\">In addition to hearing about companies' strategies, business outlook and R&D insight through general presentations, there will be opportunities for an extensive dialogue with management through Q&A sessions, networking lunches and in one-on-one and small group meetings.  To that end, we encourage you to spend as much time at the conference as possible as we have found it a great forum in which to meet a large number of key stakeholders in the medtech industry.</p><p class=\"bodytext\">We encourage you to register by <b>Friday 13 August</b>, by accessing the on-line registration form. The conference is limited to institutional investors and corporate clients only. Your registration will be confirmed by return email, but please visit our website periodically for up-to-date information on attending companies, meeting schedule and other logistical information.</p><p class=\"bodytext\">Subject to availability, there may be an opportunity for one-on-one or small group meetings. For more information and to register your specific meeting requests, please contact your Goldman Sachs sales or research representative no later than 13 August.</p><p class=\"bodytext\">We hope that you will be able to join us and enjoy our conference.</p><p class=\"bodytext\"><span class=\"darkgraytxt\"><a target=\"_blank\" href=\"mailto:Veronika.Dubajova@gs.com\">Veronika Dubajova</a>, <a target=\"_blank\" href=\"mailto:Mick.Readey@gs.com\">Mick Readey</a> and <a target=\"_blank\" href=\"mailto:James.Fitzsimmons@gs.com\">James Fitzsimmons</a></span></p>",
                PolicyLoader.Load("actv"),
                0,
                null);
        }

        [Test]
        public void TestHtml5()
        {
            TestHelper.RunExpression(
               "<FONT color=#9933ff>ADD Training</FONT>",
               PolicyLoader.Load("actv"),
               0,
               null);
            TestHelper.RunExpression(
              "<P><B><FONT color=#ff0000>PLEASE NOTE THAT ALL CANCELLATIONS WILL BE CHARGED IN FULL.</FONT></P>",
              PolicyLoader.Load("actv"),
              0,
              null);
              //TestHelper.RunExpression(
              //"<FONT style=\"face: 'Arial,\" face=\"Arial, Helvetica\" color=#ffffff size=4>",
              //PolicyLoader.Load("actv"),
              //0,
              //null);
            
        }

        [Test]
        public void TestHtml6_Puretext()
        {
            TestHelper.RunExpression(
               "Welcome to the 2003 AACC",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml7()
        {
            TestHelper.RunExpression(
               "<P style=\"MARGIN-TOP: 0px; WORD-SPACING: 0px; LINE-HEIGHT: 100%\" align=left><B>Click on the \"Download More Information\" link for the latest Agenda!</B></P>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<H5 style=\"MARGIN: 0in 0in 0pt\">",
               PolicyLoader.Load("actv"),
               0,
               null);
            TestHelper.RunExpression(
               "<P style=\"MARGIN-TOP: 0px; MARGIN-BOTTOM: 0px\">Fax # 312 944 3882</P>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml8()
        {
            TestHelper.RunExpression(
               "<IMG src=\"https://www.mireg.com/ui/18/181901/PrincipalFeb2225ClassicLogo.jpg\">&nbsp; ",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
                [Test]
        public void TestHtml9()
        {
            TestHelper.RunExpression(
               "<LI>New York City - Broadway show <EM>42nd Street.&nbsp; </EM>Don't miss your last chance to see this show.</LI>",
               PolicyLoader.Load("actv"),
               0,
               null);
            TestHelper.RunExpression(
               "<LI><STRONG><U>Friday, October 01</U></STRONG>, Planning Session &amp; Breakout Meetings 8:00 A.M. - Noon</LI>",
               PolicyLoader.Load("actv"),
               0,
               null);
                    
        }
        [Test]
        public void TestHtml10()
        {
            TestHelper.RunExpression(
               "<DIV style=\"mso-char-wrap: 1; mso-kinsoku-overflow: 1; mso-line-spacing: '100 50 0'; mso-margin-left-alt: 216\"></DIV></SPAN></SPAN></SPAN></SPAN><SPAN style=\"mso-bullet-image: 'OCUME~1SCHAFLELOCALS~1Tempmsoclip1lip_image002.gif'; mso-special-format:bullet\"><SPAN style=\"mso-bullet-image: 'OCUME~1SCHAFLELOCALS~1Tempmsoclip1lip_image003.gif';mso-special-format:bullet\"><SPAN style=\"mso-bullet-image: 'OCUME~1SCHAFLELOCALS~1Tempmsoclip1lip_image002.gif'; mso-special-format:bullet\">",
               PolicyLoader.Load("actv"),
               0,
               null);
            TestHelper.RunExpression(
               "<P class=MsoNormal style=\"MARGIN: 0in 0in 0pt 1in; TEXT-INDENT: -0.25in; tab-stops: list 1.0in\"><FONT color=#000000><SPAN style=\"FONT-FAMILY: Symbol; mso-bidi-font-family: Arial\"><FONT size=3>·</FONT></SPAN><SPAN style=\"FONT-SIZE: 7pt\"><FONT face=\"Times New Roman\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; </FONT></SPAN><SPAN style=\"FONT-SIZE: 9pt; FONT-FAMILY: Arial; mso-bidi-font-size: 8.0pt\">Demand Review <o:p></o:p></SPAN></FONT></P>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml11()
        {
            TestHelper.RunExpression(
               "<P class=MsoNormal style=\"MARGIN: 0in 0in 0pt 1in; TEXT-INDENT: -0.25in; tab-stops: list 1.0in\"><FONT color=#000000><SPAN style=\"FONT-FAMILY: Symbol; mso-bidi-font-family: Arial\"><FONT size=3>·</FONT></SPAN><SPAN style=\"FONT-SIZE: 7pt\"><FONT face=\"Times New Roman\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; </FONT></SPAN><SPAN style=\"FONT-SIZE: 9pt; FONT-FAMILY: Arial; mso-bidi-font-size: 8.0pt\">Demand Review <o:p></o:p></SPAN></FONT></P>",
               PolicyLoader.Load("actv"),
               0,
               null);
            TestHelper.RunExpression(
               "<P class=MsoBodyText2 style=\"MARGIN: 0in 0in 0pt; LINE-HEIGHT: normal\"><FONT size=3>Individual is responsible for incidentals, and any extensions before or after the meeting.</FONT></P>",
               PolicyLoader.Load("actv"),
               0,
               null);            

            TestHelper.RunExpression(
               "<UL style=\"MARGIN-TOP: 0in\" type=circle><LI class=MsoNormal style=\"MARGIN: 0in 0in 0pt; tab-stops: list 1.0in; mso-list: l0 level2 lfo1\"><SPAN style=\"FONT-SIZE: 10pt; FONT-FAMILY: Arial; mso-bidi-font-size: 12.0pt\">Airfare – please arrange your own plane ticket.<o:p></o:p></SPAN></LI>",
               PolicyLoader.Load("actv"),
               0,
               null);            
            
        }
        [Test]
        public void TestHtml12()
        {
            TestHelper.RunExpression(
               "<table border=\"1\"><tr align=\"center\" char=\".\"><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml13()
        {
            TestHelper.RunExpression(
               "<P><STRONG>Meeting, Air and Hotel Questions<BR></STRONG><BR>For&nbsp;air related questions, please contact&nbsp;Joan Brenner&nbsp;at <A href=\"mailto:jbrenner@meetings-incentives.com\">jbrenner@meetings-incentives.com</A> or (262) 835-6726.<BR>For hotel related questions, please contact Jessica Hovorka at <A href=\"mailto:jhovorka@meetings-incentives.com\">jhovorka@meetings-incentives.com</A> or (262) 835-6719.<BR>For meeting related questions, please contact Ted McDermott at <A href=\"mailto:ted.mcdermott@abbott.com\">ted.mcdermott@abbott.com</A> or (847) 935-6314.</P>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml_Js_Ajax()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">var request = new XMLHttpRequest();</script>",
               PolicyLoader.Load("actv-medium"),
               1,
               new string[] { "XMLHttpRequest" });

            TestHelper.RunExpression(
               "<script type=\"text/javascript\">var request = new ActiveXObject(\"Msxml2.XMLHTTP\");</script>",
               PolicyLoader.Load("actv-medium"),
               1,
               new string[] { "ActiveXObject" });

            TestHelper.RunExpression(
               "<script type=\"text/javascript\">var request = new activexobject(\"Msxml2.XMLHTTP\");</script>",
               PolicyLoader.Load("actv-medium"),
               1,
               new string[] { "activexobject" });
        }
        [Test]
        public void TestHtml_low_rule()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\">var request = new ActiveXObject(\"Msxml2.XMLHTTP\");</script>",
               PolicyLoader.Load("actv-low"),
               0,
               null);
        }
        [Test]
        public void TestHtml_include_script()
        {
            TestHelper.RunExpression(
               "<script type=\"text/javascript\" src=\"http://www.gold-quote.net/3BARS/gen.php?lang=en\"> ",
               PolicyLoader.Load("actv"),
               1,
               new string[] {( "<script>") });

            TestHelper.RunExpression(
               "<script type=\"text/javascript\" src=\"http://www.gold-quote.net/3BARS/gen.php?lang=en\"> ",
               PolicyLoader.Load("actv-medium"),
               1,
               new string[] { "src" });

            TestHelper.RunExpression(
               "<script type=\"text/javascript\" src=\"http://www.gold-quote.net/3BARS/gen.php?lang=en\"> ",
               PolicyLoader.Load("actv-low"),
               1,
               new string[] { "src" });
        }

        [Test]
        public void TestHtml_img_empty()
        {
            TestHelper.RunExpression(
               "<P class=MsoNormal><FONT face=\"Times New Roman\" size=3><SPAN style=\"FONT-SIZE: 12pt\"><IMG height=12 src=\"\" width=8 border=0>&nbsp;</SPAN></FONT></P></TD> ",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        [Test]
        public void TestHtml_lang_xx_xx()
        {
            TestHelper.RunExpression(
               "<SPAN lang=EN-GB style=\"FONT-SIZE: 9pt; COLOR: black; FONT-FAMILY: Arial; mso-bidi-font-size: 8.0pt; mso-ansi-language: EN-GB\"><STRONG><FONT size=3>OEC LOCAL GUIDELINES/REGULATIONS<o:p></o:p></FONT></STRONG></SPAN>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_Del_datetime()
        {
            TestHelper.RunExpression(
               "<DEL datetime=\"2003-12-19T16:24\" cite=\"mailto:faheyam\">",
               PolicyLoader.Load("actv"),
               0,
               null);
        }

        [Test]
        public void TestHtml_table_borderColor()
        {
            TestHelper.RunExpression(
               "<TABLE id=\"AutoNumber1\" style=\"BORDER-COLLAPSE: collapse\" borderColor=\"#111111\" height=596 cellSpacing=0 cellPadding=0 width=617 border=0>",
               PolicyLoader.Load("actv"),
               0,
               null);
        }
        
        [Test]
        public void TestHtml_td_valign()
        {
            TestHelper.RunExpression(
               "<TD vAlign=top width=\"30%\"><FONT face=Arial size=2>Sunday, July 11</FONT></TD>",
               PolicyLoader.Load("actv"),
               0,
               null);

            TestHelper.RunExpression(
               "<TD vAlign=center width=165 height=560>",
               PolicyLoader.Load("actv"),
               0,
               null);            
        }

        [Test]
        public void TestHtml_text_autospace()
        {
            TestHelper.RunExpression(
               "<P class=MsoBodyText2 style=\"MARGIN: 0in 0in 0pt; LINE-HEIGHT: normal; TEXT-AUTOSPACE: ideograph-numeric; mso-layout-grid-align: auto\"><FONT size=3>Business Managers / Product Managers / Medical Managers (optional) / Sales Trainers (optional).<SPAN style=\"mso-spacerun: yes\">&nbsp;&nbsp; </SPAN></FONT></P>",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }

        [Test]
        public void TestHtml_pastdeadline()
        {
            TestHelper.RunExpression(
               "<div align=\"center\">   <table border=\"4\" cellpadding=\"8\" width=\"574\" id=\"table1\" style=\"border-collapse: collapse\" bordercolor=\"#0000FF\">    <tr>     <td>     <p align=\"left\"><b><font face=\"Arial\" size=\"3\" color=\"#FF0000\">Registration is      closed.</font></b></p>     <p align=\"left\"><b><font face=\"Arial\" size=\"3\" color=\"#FF0000\">     For any questions regarding your registration, please contact:</font></b><p align=\"left\">     <b><font face=\"Arial\" size=\"3\" color=\"#FF0000\">     Kristy      Lindsey (kristy.k.lindsey@urs.com) at 208-386-7456 or<br>     Cheryl      Davis-West (cheryl.davis-west@urs.com) at 208-386-6160</font></b></td>    </tr>   </table>  </div>",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }
                [Test]
        public void TestHtml_font_color_without_sharp()
        {
            TestHelper.RunExpression(
               "<b><font color=\"003399\">In this next live open storage management software demo, you'll discover how easy it is to: </b></font>",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }
                        [Test]
        public void TestHtml_font_colo_without_quote()
        {
            TestHelper.RunExpression(
               "<STRONG><FONT color=#003a7e>In this live solution demo, you'll discover how easy it is to:</FONT></STRONG> ",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }
        [Test]
        public void TestHtml_table_bordercolor()
        {
            TestHelper.RunExpression(
               "<table bordercolor=\"#000000\" cellspacing=\"2\" cellpadding=\"2\" width=\"551\" bgcolor=\"#000000\" border=\"2\">",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }

        [Test]
        public void TestHtml_margin_auto()
        {
            TestHelper.RunExpression(
               "<P class=bodycopy style=\"MARGIN: auto 0in\">",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }
        
        [Test]
        public void TestPerformance_1000times_shorttext()
        {
            Stopwatch stopWatch = Stopwatch.StartNew();
            for (int i = 0; i < 1000; i++)
            {
                TestHelper.RunExpression(
                   "<table border=\"1\"><tr align=\"center\" char=\".\"><th>Month</th><th>Savings</th></tr><tr><td>January</td><td>$100</td></tr></table>",
                   PolicyLoader.Load("actv"),
                   0,
                   null);
            }
            stopWatch.Stop();
            TimeSpan ts = stopWatch.Elapsed;
            Assert.Less(ts.Milliseconds,1000);
        }

        [Test]
        public void TestPerformance_1000times_longtext()
        {
            Stopwatch stopWatch = Stopwatch.StartNew();
            for (int i = 0; i < 1000; i++)
            {
                TestHelper.RunExpression(
                   "<table class=\"Contents\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" id=\"AdvLayoutOuterMostTable\"><TR><TD colspan=\"3\" VALIGN=\"TOP\" class=\"AdvLayoutHeader\"><!--Begin Header Contents--><div Class=\"HeaderContents\">  <table width=\"100%\" height=\"100\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">    <tr>       <td width=\"11\" height=\"7\"><img src=\"/art/cir_top_left.jpg\" width=\"11\" height=\"7\"></td>      <td bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"7\"></td>      <td width=\"11\"><img src=\"/art/cir_top_right.jpg\" width=\"11\" height=\"7\"></td>    </tr>    <tr>       <td bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"86\"></td>      <td bgcolor=\"#FFFFFF\"><table width=\"738\" border=\"0\" cellspacing=\"0\" cellpadding=\"5\">          <tr>             <td width=\"160\"><img src=\"/art/logo.gif\" width=\"141\" height=\"39\"></td>            <td align=\"center\" class=\"HeaderText\">Company Trip</td>          </tr>        </table></td>      <td bgcolor=\"#FFFFFF\"> </td>    </tr>    <tr>       <td height=\"7\"><img src=\"/art/cir_bottom_left.jpg\" width=\"11\" height=\"7\"></td>      <td bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"7\"></td>      <td><img src=\"/art/cir_bottom_right.jpg\" width=\"11\" height=\"7\"></td>    </tr>  </table></div><!--End Header Contents--></TD></TR><TR><TD colspan=\"3\" VALIGN=\"TOP\" class=\"AdvLayoutTopNav\"></TD></TR><TR><TD VALIGN=\"TOP\" NOWRAP class=\"AdvLayoutLeftNav\"><!--Begin Left Navigation Contents--><div class=\"LeftNav\">	<table width=\"180\" height=\"475\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\">          <tr>             <td width=\"11\" height=\"7\"><img src=\"/art/cir_top_left.jpg\" width=\"11\" height=\"7\"></td>            <td bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"7\"></td>            <td width=\"11\"><img src=\"/art/cir_top_right.jpg\" width=\"11\" height=\"7\"></td>          </tr>          <tr>             <td rowspan=\"2\" bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"461\"></td>            <td valign=\"top\" bgcolor=\"#FFFFFF\">               <table width=\"158\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" class=\"NavText\">                <tr>                  <td align=\"left\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"15\"></td>                </tr>                <tr>                   <td align=\"left\"> <p> <a href=\"https://localhost/rsvp/invitation/invitation.asp?donotrefresh=1\"> - Introduction</a><br>                      <a href=\"https://localhost/rsvp/invitation/registration.asp\">- Registration</a><br>                     <a href=\"https://localhost/rsvp/invitation/accommodationregistration.asp \">- Accommodation</a><br>                      <a href=\"https://localhost/rsvp/invitation/orderpreview.asp\">- Check Out</a><br>		</p></td>                </tr>              </table>		</td>            <td rowspan=\"2\" bgcolor=\"#FFFFFF\"> </td>          </tr>          <tr>            <td valign=\"bottom\" bgcolor=\"#FFFFFF\"><table width=\"158\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" class=\"NavText\">                <tr>                   <td><p>Contact:<br>                      Planer Name<br>                      <a href=\"/\">planer@companyname.com</a><br>                      415-694-9509 </p></td>                </tr>              </table>              <br>              <br> </td>          </tr>          <tr>             <td height=\"7\"><img src=\"/art/cir_bottom_left.jpg\" width=\"11\" height=\"7\"></td>            <td bgcolor=\"#FFFFFF\"><img src=\"/art/spacer.gif\" width=\"1\" height=\"7\"></td>            <td><img src=\"/art/cir_bottom_right.jpg\" width=\"11\" height=\"7\"></td>          </tr>        </table>	<td class=\"Contents AdvLayoutMainContent\" VALIGN=\"TOP\">	<div class=\"BodyContents\">  	<!--Begin Body Contents-->    				<P class=\"EPRegNotifyText\">Planner Mode -- Planner Mode -- Planner Mode -- Planner Mode -- Planner Mode -- Planner Mode -- Planner Mode -- Planner Mode</P>				:( <pre><code>&lt;!--这是一段注释。注释不会在浏览器中显示。--&gt;</code>&lt;p&gt;这是一段普通的段落。&lt;/p&gt;&lt;br/&gt;</pre><br /><span style=\"background-color: yellow\">aaaaaaa</span>		<!--Displaying description-->			<span class=\"small\" id=\"ICannotAttend\">	</span>	    <!--End Body Contents-->    </div>    </td><TD VALIGN=\"TOP\" colspan=\"1\" class=\"AdvLayoutRightNav\"></TD></TR><TR><TD VALIGN=\"TOP\" colspan=\"3\" class=\"AdvLayoutFooter\"><!--Begin Footer Contents--><div class=\"FooterContents\"><table width=\"100%\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">    <tr>      <td align=\"center\" class=\"FooterText\">? 2004 - 2007 StarCIte Inc. All RIghts         Reserved.<br>        Powered by <img src=\"/art/logo_powered_by.gif\" width=\"75\" height=\"20\"></td>    </tr></table></div><!--End Footer Contents--></TD></TR></table>",
                   PolicyLoader.Load("actv"),
                   0,
                   null);
            }
            stopWatch.Stop();
            TimeSpan ts = stopWatch.Elapsed;
            Assert.Less(ts.Milliseconds, 2000);
        }

        [Test]
        public void TestHtml_production_error()
        {
            TestHelper.RunExpression(
               "<div style=\"text-justify: inter-ideograph; margin: 0in 0in 0pt; text-align: justify\"><div style=\"text-justify: inter-ideograph; text-align: justify\"><font size=\"2\"><br /></font></div><p><span style=\"font-size: 10pt\"><span style=\"font-family: Arial\">Thank you for your interest in the SAR-245408 (XL147) Investigators Meeting at the San Antonio Breast Cancer Symposium (SABCS)<br /><br />To register for this Investigators Meeting please click &quot;Registration&quot; on the left navigation.<br /><br /><u>Meeting Date and Time<br /></u>Monday, December 5, 2011, 5:00-8:00 pm CDT<br /><br /><u>Meeting Location<br /></u><span style=\"\"><span><span style=\"\"><span>Fi",
               PolicyLoader.Load("actv"),
               0,
               null);     
        }
        [Test]
        public void TestHtml_hr_color()
        {
            TestHelper.RunExpression(
            "<hr color=\"#000000\" size=\"1\" />",
               PolicyLoader.Load("actv"),
               0, null);
        }
        [Test]
        public void TestHtml_align_justify()
        {
            TestHelper.RunExpression(
            "<FONT color=#5e5a59 size=2 align=\"justify\">",
               PolicyLoader.Load("actv"),
               0, null);
        }
        [Test]
        public void TestHtml_br_moz()
        { 
            TestHelper.RunExpression(
            "<br type=\"_moz\" />",
               PolicyLoader.Load("actv"),
               0, null);
            
        }

        [Test]
        public void TestHtml_b_emptydata()
        {
            TestHelper.RunExpression(
            "<b></b>",
               PolicyLoader.Load("actv"),
               0, null);

        }
        [Test]
        public void TestHtml_travel_page_data()
        {
            TestHelper.RunExpression(
            "I <B>do not</B> require travel.",
               PolicyLoader.Load("actv"),
               0, null);
        }
        [Test]
        public void TestHtml_RGB_Color()
        { 
            TestHelper.RunExpression(
            "<div style=\"color:rgb(255, 0, 0)\"> require travel</div>",
               PolicyLoader.Load("actv"),
               0, null);
            TestHelper.RunExpression(
            "<div style=\"color:rgb(255,0,0)\"> require travel</div>",
               PolicyLoader.Load("actv"),
               0, null);           
        }
                [Test]
        public void TestHtml_font_size()
        { 
            TestHelper.RunExpression(
            "<font face=arial size=3>",
               PolicyLoader.Load("actv"),
               0, null);

            TestHelper.RunExpression(
            "<span style=\"font-size:9.0pt;font-family:'Arial','sans-serif';mso-fareast-font-family:'Times New Roman';color:#444444\">",
               PolicyLoader.Load("actv"),
               0, null);
                    
        }
        [Test]
        public void TestHtml_span_color()
        {
            TestHelper.RunExpression(
                "<div style=&quot;color:#015C93&quot;>Dear</div>",
                PolicyLoader.Load("actv"),
                0, null);

//            TestHelper.RunExpression(
//"<span style=&quot;color: #015C93&quot;>Dear</span>",
//   PolicyLoader.Load("actv"),
//   0, null);
        
        }
        [Test]
        public void TestHtml_low_onclick()
        {
            TestHelper.RunExpression(
               "<div onclick=\"window.close();\">Dear</div>",
               PolicyLoader.Load("actv-medium"),
               0, null);

             TestHelper.RunExpression(
                "<div onclick=\"window.close();\">Dear</div>",
                PolicyLoader.Load("actv-low"),
                0, null);

             TestHelper.RunExpression(
                "<div onmousedown=\"window.close();\">Dear</div>",
                PolicyLoader.Load("actv-low"),
                0, null);     
        }
    }
}
