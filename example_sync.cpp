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
    cls::LogGroup loggroup;
    auto log = loggroup.add_logs();
    log->set_time(time(NULL));
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

