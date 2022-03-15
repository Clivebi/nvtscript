if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804436" );
	script_version( "2021-10-05T12:25:15+0000" );
	script_bugtraq_id( 56733 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2014-04-22 13:06:41 +0530 (Tue, 22 Apr 2014)" );
	script_name( "Oracle OpenSSO Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/23004" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80368" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2012110221" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5114.php" );
	script_tag( name: "summary", value: "Oracle OpenSSO is prone to multiple cross-site scripting
  (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an:

  - Improper validation of 'dob_Day', 'dog_Month', 'dog_Year', 'givenname',
  'name', and 'sn' parameters upon submission to the cmp_generate_tmp_pw.tiles
  script.

  - Improper validation of 'dob_day', 'dob_Month', 'dob_Year', 'givenname',
  'mail', 'sn', 'x', and 'y' parameters upon submission to UI/Login in
  the ResetPassword module." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to create a specially crafted
  request that would execute arbitrary script code in a user's browser within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Oracle OpenSSO 8.0 Update 2 Patch3 Build 6.1" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

