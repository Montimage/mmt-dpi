<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
  <head>
<title>MMT-Security Results</title>
<link href="properties.css" rel="stylesheet" type="text/css" />
</head>

  <body>

<h2>Security Properties</h2>
    <table id="one-column-emphasis" width="80%">
      <colgroup>
    	<col class="oce-first" />
      </colgroup>
      <tr>
        <td width="15%"><strong>Project Name:</strong></td>
        <td width="85%">Advanced monitoring of ad-hoc network nodes for security checking using the MMT tool</td>
      </tr>
      <tr>
        <td><strong>Project Description:</strong></td>
        <td>Montimage Monitoring Tool (MMT) is a functional and security analysis tool that verifies the network traffic trace of an application or protocol against a set of properties called MMT-Security properties. MMT can be
executed against a recorded packet trace file or live on a network interface for real time analysis. In this demonstrator, MMT was applied to the radio protocol traces of Thales group provided by OMNET simulator.</td>
      </tr>
      <!--tr>
        <td><strong>Demonstrator parameters:</strong></td>
        <td>6 security rules were specified and checked using MMT. The results are provided in the next sections</td>
      </tr-->
    </table>
    <hr />

  <h3>List of properties to detect</h3>
  <table id="box-table-a" width="80%" >
    <tr>
      <th>Pid</th>
	  <th>Type</th>
      <th colspan="3">Property description</th>
    </tr>
    <xsl:for-each select="beginning/property">
    <tr>
	  <xsl:variable name="nbev"><xsl:value-of select="nbevents"/></xsl:variable>
      <td ><xsl:value-of select="@property_id"/></td>
       <td >
	  <xsl:choose>
	  <xsl:when test="@type_property='SECURITY_RULE'">
	    <img src='images/OKShield-icon.png' width='32' height='32' alt='Security rule'/>
	  </xsl:when>
	  <xsl:when test="@type_property='ATTACK'">
	    <img src='images/Attack-icon.png' width='32' height='32' alt='Attack'/>
	  </xsl:when>
	  </xsl:choose>
	  </td>
	  <td colspan="3"><xsl:value-of select="@description"/></td>
	</tr>
	
	<xsl:for-each select="event">
	<tr>
	  <td width="5%"></td>
	  <td width="8%">EVENT <xsl:value-of select="@event_id"/></td>
	  <td width="87%"><xsl:value-of select="@description"/></td>
	</tr>
	<tr>
	  <td></td>
	  <td></td>
	  <td><xsl:value-of select="@boolean_expression"/></td>
        </tr>
	</xsl:for-each>
    </xsl:for-each>
  </table>
  	
 
  
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>
