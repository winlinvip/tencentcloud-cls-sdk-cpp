#include <stdlib.h>

#include "client.h"
#include "common.h"
#include "cls_logs.pb.h"
#include <string>
#include <iostream>
#include <unistd.h>
#include <memory>

using namespace tencent_log_sdk_cpp_v2;
using namespace std;

class UserResult : public CallBack {
public:
    UserResult() = default;

    ~UserResult() = default;

    void Success(PostLogStoreLogsResponse result) override { std::cout << result.Printf() << std::endl; }

    void Fail(PostLogStoreLogsResponse result) override {
        std::cout << result.Printf() << std::endl;
        std::cout << result.loggroup_.ShortDebugString().c_str() << std::endl;
    }
};

int main(int argc, char **argv) {
    std::string region = getenv("REGION") ? getenv("REGION") : "ap-guangzhou";
    std::string ak_id = getenv("AKID") ? getenv("AKID") : "";
    std::string ak_secret = getenv("AKSECRET") ? getenv("AKSECRET") : "";
    std::string topic = getenv("TOPIC") ? getenv("TOPIC") : "";

    string endpoint = region + ".cls.tencentcs.com";
    cout << "region:" << region << ", endpoint:" << endpoint << ", ak:" << ak_id << ", secret:" << ak_secret.length()
         << "B" << ", topic:" << topic << endl;
    if (ak_id.empty() || ak_secret.empty() || topic.empty()) {
        cout << "No config" << endl;
        exit(-1);
    }

    std::shared_ptr<LOGClient> ptr = std::make_shared<LOGClient>(
            endpoint, ak_id, ak_secret,
            LOG_REQUEST_TIMEOUT, LOG_CONNECT_TIMEOUT,
            "127.0.0.1", false
    );

    auto now = time(NULL);
    printf("now=%lx\n", now);

    // Log in PB, see https://developers.google.com/protocol-buffers/docs/encoding
    //      0a 30 (LogGroupList.logGroupList, ID=1, LD=0x30=48B)
    //          0a 23 (LogGroup.logs, ID=1, LD=0x23=35B)
    //              08 (Log.time, ID=1, VAR = 0x62ece79d = 1659692957 Friday, August 5, 2022 9:49:17 AM)
    //                  9d cf b3 97 06
    //              12 1b (Log.contents, ID=2, LD=0x1b=27B)
    //                  0a 07 (Content.key, ID=1, LD=0x07=7B)
    //                      63 6f 6e 74 65 6e 74 (string="content")
    //                  12 10 (Content.value, ID=2, LD=0x10=16B)
    //                      74 68 69 73 20 6d 79 20 74 65 73 74 20 6c 6f 67 (string="this my test log")
    //          22 09 (LogGroup.source, ID=4, LD=0x09=9B)
    //              31 32 37 2e 30 2e 30 2e 31 (string="127.0.0.1")
    cls::LogGroup loggroup;
    auto log = loggroup.add_logs();
    log->set_time(now);
    auto content = log->add_contents();
    content->set_key("content");
    content->set_value("this my test log");
    loggroup.set_source("127.0.0.1");

    PostLogStoreLogsResponse ret;
    try {
        for (int i = 0; i < 1; ++i) {
            ret = ptr->PostLogStoreLogs(topic, loggroup);
            printf("%s\n", ret.Printf().c_str());
        }
    }
    catch (LOGException &e) {
        cout << e.GetErrorCode() << ":" << e.GetMessage() << endl;
    }
    return 0;
}

