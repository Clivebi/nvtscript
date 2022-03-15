if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-February/019235.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881599" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-02-15 11:15:33 +0530 (Fri, 15 Feb 2013)" );
	script_cve_id( "CVE-2012-4545" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2013:0250" );
	script_name( "CentOS Update for elinks CESA-2013:0250 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'elinks'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "elinks on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "ELinks is a text-based web browser. ELinks does not display any images, but
  it does support frames, tables, and most other HTML tags.

  It was found that ELinks performed client credentials delegation during the
  client-to-server GSS security mechanisms negotiation. A rogue server could
  use this flaw to obtain the client's credentials and impersonate that
  client to other servers that are using GSSAPI. (CVE-2012-4545)

  This issue was discovered by Marko Myllynen of Red Hat.

  All ELinks users are advised to upgrade to this updated package, which
  contains a backported patch to resolve the issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "elinks", rpm: "elinks~0.11.1~8.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

