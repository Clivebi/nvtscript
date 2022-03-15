if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882401" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-19 06:18:36 +0100 (Fri, 19 Feb 2016)" );
	script_cve_id( "CVE-2016-1930", "CVE-2016-1935" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2016:0258 centos5" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and
newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2016-1930, CVE-2016-1935)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Christian Holler, Nils Ohlmeier, Gary
Kwong, Jesse Ruderman, Carsten Book, Randell Jesup, and Aki Helin as the
original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 38.6.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.6.0, which corrects these issues. After
installing the update, Thunderbird must be restarted for the changes to
take effect." );
	script_tag( name: "affected", value: "thunderbird on CentOS 5" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0258" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-February/021708.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~38.6.0~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

