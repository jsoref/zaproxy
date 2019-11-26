<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  version="1.0"
  >
  <xsl:output method="html"/>

  <xsl:template match="/OWASPZAPReport"> 

<html>
<head>
<!-- ZAP: rebrand -->
<title>ZAP Scanning Report</title>

<style>
body{
  font-family: "Helvetica Neue",Helvetica,Arial,sans-serif;
  color: #000;
  font-size: 13px;
}
h1{
  text-align: center;
  font-weight: bold;
  font-size: 32px
}
h3{
  font-size: 16px;
}
table{
  border: none;
  font-size: 13px;
}
td, th {
  padding: 3px 4px;
  word-break: break-word;
}
th{
  font-weight: bold;
}
.results th{
  text-align: left;
}
.spacer{
  margin: 10px;
}
.spacer-lg{
  margin: 40px;
}
.indent1{
  padding: 4px 20px;
}
.indent2{
  padding: 4px 40px;
}
.risk-high{
  background-color: red;
  color: #FFF;
}
.risk-medium{
  background-color: orange;
  color: #FFF;
}
.risk-low{
  background-color: yellow;
  color: #000;
}
.risk-info{
  background-color: blue;
  color: #FFF;
}
.summary th{
  color: #FFF;
}
</style>
</head>

<body>
<!-- ZAP: rebrand -->
<h1>
<img src="data:," />
ZAP Scanning Report
</h1>

<p>
<xsl:apply-templates select="text()"/>
</p>
<h3>Summary of Alerts</h3>
<table width="45%" class="summary">
  <tr bgcolor="#666666"> 
    <th width="45%" height="24">Risk 
      Level</th>
    <th width="55%" align="center">Number 
      of Alerts</th>
  </tr>
  <tr bgcolor="#e8e8e8"> 
    <td><a href="#high">High</a></td>
    <td align="center">
      <xsl:value-of select="count(descendant::alertitem[riskcode='3'])"/>
    </td>
  </tr>
  <tr bgcolor="#e8e8e8"> 
    <td><a href="#medium">Medium</a></td>
    <td align="center">
      <xsl:value-of select="count(descendant::alertitem[riskcode='2'])"/>
    </td>
  </tr>
  <tr bgcolor="#e8e8e8"> 
    <td><a href="#low">Low</a></td>
    <td align="center">
      <xsl:value-of select="count(descendant::alertitem[riskcode='1'])"/>
    </td>
  </tr>
  <tr bgcolor="#e8e8e8"> 
    <td><a href="#info">Informational</a></td>
    <td align="center">
      <xsl:value-of select="count(descendant::alertitem[riskcode='0'])"/>
    </td>
  </tr>
</table>
<div class="spacer-lg"></div>
<h3>Alert Detail</h3>

<xsl:apply-templates select="descendant::alertitem">
  <xsl:sort order="descending" data-type="number" select="riskcode"/>
  <xsl:sort order="descending" data-type="number" select="confidence"/>
</xsl:apply-templates>
</body>
</html>
</xsl:template>

  <!-- Top Level Heading -->
  <xsl:template match="alertitem">
<div class="spacer"></div>
<table width="100%" class="results">
<xsl:apply-templates select="text()|name|desc|uri|method|param|attack|evidence|instances|count|otherinfo|solution|reference|cweid|wascid|sourceid|p|br|wbr|ul|li"/>
</table>
  </xsl:template>

  <xsl:template match="name[following-sibling::riskcode='3']">
  <tr height="24" class="risk-high">
    <th width="20%">
      <a name="high"/>
      <xsl:value-of select="following-sibling::riskdesc"/>
    </th>
    <th width="80%">
      <xsl:apply-templates select="text()"/>
    </th>
  </tr>
  </xsl:template>

  <xsl:template match="name[following-sibling::riskcode='2']">
  <!-- ZAP: Changed the medium colour to orange -->
  <tr height="24" class="risk-medium">
    <th width="20%">
      <a name="medium"/>
      <xsl:value-of select="following-sibling::riskdesc"/>
    </th>
    <th width="80%">
      <xsl:apply-templates select="text()"/>
    </th>
  </tr>

  </xsl:template>
  <xsl:template match="name[following-sibling::riskcode='1']">
  <!-- ZAP: Changed the low colour to yellow -->
  <tr height="24" class="risk-low">
    <a name="low"/>
    <th width="20%">
    <xsl:value-of select="following-sibling::riskdesc"/>
    </th>
    <th width="80%">
      <xsl:apply-templates select="text()"/>
    </th>
  </tr>
  </xsl:template>

  <xsl:template match="name[following-sibling::riskcode='0']">
  <tr height="24" class="risk-info">
    <th width="20%">
      <a name="info"/>
      <xsl:value-of select="following-sibling::riskdesc"/>
    </th>
    <th width="80%">
      <xsl:apply-templates select="text()"/>
    </th>
  </tr>
  </xsl:template>


<!--
  <xsl:template match="riskdesc">
  <tr>
    <td width="20%">Risk</td> 
    <td width="20%">
    <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>
-->

  <xsl:template match="desc">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">Description</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  <TR vAlign="top"> 
    <TD colspan="2"> </TD>
  </TR>
  
  </xsl:template>

  <xsl:template match="uri">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">URL</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>

  <xsl:template match="method">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">Method</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>

  <xsl:template match="param">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">Parameter</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="attack">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">Attack</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="evidence">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">Evidence</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="instances/instance/uri">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent1">URL</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>

  <xsl:template match="instances/instance/method">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent2">Method</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>

  <xsl:template match="instances/instance/param">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent2">Parameter</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="instances/instance/attack">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent2">Attack</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="instances/instance/evidence">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%" class="indent2">Evidence</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="count">
  <xsl:if test="text() !=''">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">Instances</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:if>
  </xsl:template>

  <xsl:template match="otherinfo">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">Other information</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>

  <TR vAlign="top"> 
    <TD colspan="2"> </TD>
  </TR>
  </xsl:template>

  <xsl:template match="solution">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">Solution</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>

  <xsl:template match="reference">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">Reference</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>
  
  <xsl:template match="cweid">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">CWE Id</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>
  
  <xsl:template match="wascid">
  <tr bgcolor="#e8e8e8"> 
    <td width="20%">WASC Id</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>
  
  <xsl:template match="sourceid">
  <tr bgcolor="#e8e8e8">
    <td width="20%">Source ID</td>
    <td width="80%">
      <xsl:apply-templates select="text()|*"/>
    </td>
  </tr>
  </xsl:template>
  
  <xsl:template match="p">
  <p align="justify">
  <xsl:apply-templates select="text()|*"/>
  </p>
  </xsl:template> 

  <xsl:template match="br">
  <br/>
  <xsl:apply-templates/>
  </xsl:template> 

  <xsl:template match="ul">
  <ul>
  <xsl:apply-templates select="text()|*"/>
  </ul>
  </xsl:template> 

  <xsl:template match="li">
  <li>
  <xsl:apply-templates select="text()|*"/>
  </li>
  </xsl:template> 
  
  <xsl:template match="wbr">
  <wbr/>
  <xsl:apply-templates/>
  </xsl:template> 

</xsl:stylesheet>
