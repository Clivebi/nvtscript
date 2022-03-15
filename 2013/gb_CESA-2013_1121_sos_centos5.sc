if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881767" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-08-01 18:43:21 +0530 (Thu, 01 Aug 2013)" );
	script_cve_id( "CVE-2012-2664" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "CentOS Update for sos CESA-2013:1121 centos5" );
	script_tag( name: "affected", value: "sos on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The sos package contains a set of tools that gather information from system
hardware, logs and configuration files. The information can then be used
for diagnostic purposes and debugging.

The sosreport utility collected the Kickstart configuration file
('/root/anaconda-ks.cfg'), but did not remove the root user's password from
it before adding the file to the resulting archive of debugging
information. An attacker able to access the archive could possibly use this
flaw to obtain the root user's password. '/root/anaconda-ks.cfg' usually
only contains a hash of the password, not the plain text password.
(CVE-2012-2664)

Note: This issue affected all installations, not only systems installed via
Kickstart. A '/root/anaconda-ks.cfg' file is created by all installation
types.

The utility also collects yum repository information from
'/etc/yum.repos.d' which in uncommon configurations may contain passwords.
Any http_proxy password specified in these files will now be automatically
removed. Passwords embedded within URLs in these files should be manually
removed or the files excluded from the archive.

All users of sos are advised to upgrade to this updated package, which
contains a backported patch to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1121" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-July/019885.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sos'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "sos", rpm: "sos~1.7~9.62.el5_9.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

