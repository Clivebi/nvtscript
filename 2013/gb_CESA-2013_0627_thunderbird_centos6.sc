if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019642.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881688" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-15 09:52:44 +0530 (Fri, 15 Mar 2013)" );
	script_cve_id( "CVE-2013-0787" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2013:0627" );
	script_name( "CentOS Update for thunderbird CESA-2013:0627 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "thunderbird on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

  A flaw was found in the processing of malformed content. Malicious content
  could cause Thunderbird to crash or execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2013-0787)

  Red Hat would like to thank the Mozilla project for reporting this issue.
  Upstream acknowledges VUPEN Security via the TippingPoint Zero Day
  Initiative project as the original reporter.

  Note: This issue cannot be exploited by a specially-crafted HTML mail
  message as JavaScript is disabled by default for mail messages. It could
  be exploited another way in Thunderbird, for example, when viewing the full
  remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  corrects this issue. After installing the update, Thunderbird must be
  restarted for the changes to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~17.0.3~2.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

