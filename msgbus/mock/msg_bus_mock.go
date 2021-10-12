// Code generated by MockGen. DO NOT EDIT.
// Source: ./message_bus.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	msgbus "github.com/Mydawn2/CLkey-common/msgbus"
	gomock "github.com/golang/mock/gomock"
)

// MockMessageBus is a mock of MessageBus interface.
type MockMessageBus struct {
	ctrl     *gomock.Controller
	recorder *MockMessageBusMockRecorder
}

// MockMessageBusMockRecorder is the mock recorder for MockMessageBus.
type MockMessageBusMockRecorder struct {
	mock *MockMessageBus
}

// NewMockMessageBus creates a new mock instance.
func NewMockMessageBus(ctrl *gomock.Controller) *MockMessageBus {
	mock := &MockMessageBus{ctrl: ctrl}
	mock.recorder = &MockMessageBusMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMessageBus) EXPECT() *MockMessageBusMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockMessageBus) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockMessageBusMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockMessageBus)(nil).Close))
}

// Publish mocks base method.
func (m *MockMessageBus) Publish(topic msgbus.Topic, payload interface{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Publish", topic, payload)
}

// Publish indicates an expected call of Publish.
func (mr *MockMessageBusMockRecorder) Publish(topic, payload interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Publish", reflect.TypeOf((*MockMessageBus)(nil).Publish), topic, payload)
}

// PublishSafe mocks base method.
func (m *MockMessageBus) PublishSafe(topic msgbus.Topic, payload interface{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PublishSafe", topic, payload)
}

// PublishSafe indicates an expected call of PublishSafe.
func (mr *MockMessageBusMockRecorder) PublishSafe(topic, payload interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublishSafe", reflect.TypeOf((*MockMessageBus)(nil).PublishSafe), topic, payload)
}

// Register mocks base method.
func (m *MockMessageBus) Register(topic msgbus.Topic, sub msgbus.Subscriber) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Register", topic, sub)
}

// Register indicates an expected call of Register.
func (mr *MockMessageBusMockRecorder) Register(topic, sub interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockMessageBus)(nil).Register), topic, sub)
}

// MockSubscriber is a mock of Subscriber interface.
type MockSubscriber struct {
	ctrl     *gomock.Controller
	recorder *MockSubscriberMockRecorder
}

// MockSubscriberMockRecorder is the mock recorder for MockSubscriber.
type MockSubscriberMockRecorder struct {
	mock *MockSubscriber
}

// NewMockSubscriber creates a new mock instance.
func NewMockSubscriber(ctrl *gomock.Controller) *MockSubscriber {
	mock := &MockSubscriber{ctrl: ctrl}
	mock.recorder = &MockSubscriberMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSubscriber) EXPECT() *MockSubscriberMockRecorder {
	return m.recorder
}

// OnMessage mocks base method.
func (m *MockSubscriber) OnMessage(arg0 *msgbus.Message) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnMessage", arg0)
}

// OnMessage indicates an expected call of OnMessage.
func (mr *MockSubscriberMockRecorder) OnMessage(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnMessage", reflect.TypeOf((*MockSubscriber)(nil).OnMessage), arg0)
}

// OnQuit mocks base method.
func (m *MockSubscriber) OnQuit() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "OnQuit")
}

// OnQuit indicates an expected call of OnQuit.
func (mr *MockSubscriberMockRecorder) OnQuit() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OnQuit", reflect.TypeOf((*MockSubscriber)(nil).OnQuit))
}
