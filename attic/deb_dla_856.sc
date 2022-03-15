if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890856" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_name( "Debian LTS: Security Advisory for tzdata (DLA-856-1)" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-01-15 00:00:00 +0100 (Mon, 15 Jan 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00013.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_tag( name: "affected", value: "tzdata on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2017a-0+deb7u1.

We recommend that you upgrade your tzdata packages." );
	script_tag( name: "summary", value: "This update includes the changes in tzdata 2017a. Notable
changes are:

  - Mongolia no longer observes DST.

  - Magallanes region diverges from Santiago starting 2017-05-13,
the America/Punta_Arenas zone has been added.

  This NVT has been deprecated as it doesn't have any security relevance." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

