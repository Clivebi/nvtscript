if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882393" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-17 06:27:23 +0100 (Wed, 17 Feb 2016)" );
	script_cve_id( "CVE-2015-7529" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for sos CESA-2016:0188 centos7" );
	script_tag( name: "summary", value: "Check the version of sos" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The sos package contains a set of utilities
that gather information from system hardware, logs, and configuration files.
The information can then be used for diagnostic purposes and debugging.

An insecure temporary file use flaw was found in the way sos created
certain sosreport files. A local attacker could possibly use this flaw to
perform a symbolic link attack to reveal the contents of sosreport files,
or in some cases modify arbitrary files and escalate their privileges on
the system. (CVE-2015-7529)

This issue was discovered by Mateusz Guzik of Red Hat.

This update also fixes the following bug:

  * Previously, the sosreport tool was not collecting the /var/lib/ceph and
/var/run/ceph directories when run with the ceph plug-in enabled, causing
the generated sosreport archive to miss vital troubleshooting information
about ceph. With this update, the ceph plug-in for sosreport collects these
directories, and the generated report contains more useful information.
(BZ#1291347)

All users of sos are advised to upgrade to this updated package, which
contains backported patches to correct these issues." );
	script_tag( name: "affected", value: "sos on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:0188" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-February/021704.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "sos", rpm: "sos~3.2~35.el7.centos.3", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

