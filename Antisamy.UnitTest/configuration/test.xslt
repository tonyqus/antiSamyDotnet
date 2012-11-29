<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
<b>Tag White List</b><br />
    <xsl:for-each select="/anti-samy-rules/tag-rules/tag">
	<xsl:if test="not(@action='remove')">
		<b><xsl:value-of select="@name"/></b><br/>
		<xsl:for-each select="attribute">
			<xsl:value-of select="@name"/>,
		</xsl:for-each>
		<br/>
	</xsl:if>
    </xsl:for-each>
<br />
<b>Global Attribute White List</b><br />	
    <xsl:for-each select="/anti-samy-rules/global-tag-attributes/attribute">
     <xsl:value-of select="@name"/><br/>
    </xsl:for-each>
<br />
<b>Common Attribute White List</b><br />	
    <xsl:for-each select="/anti-samy-rules/common-attributes/attribute">
     <xsl:value-of select="@name"/><br/>
    </xsl:for-each>
<br />
<b>CSS Property White List</b><br />	
    <xsl:for-each select="/anti-samy-rules/css-rules/property">
     <xsl:value-of select="@name"/><br/>
    </xsl:for-each>
	
</xsl:template>

</xsl:stylesheet>